// Node library requirements on main.js or server.js

// var crypto = require('crypto');
// var request = require('request');
// var rp = require('request-promise');

var request = require('request');

var Client = function(clientId, secretKey, isBeta = false, serverAddr = '') {
  function init() {
    // Initialize SPARCS SSO Client
    // :param clientId: your client id
    // :param secretKey: your secret key
    // :param isBeta: true iff you want to use SPARCS SSO beta server
    // :param serverAddr: SPARCS SSO server addr (only for testing)
    if (isBeta) {
      this.DOMAIN = this.BETA_DOMAIN;
    } else {
      this.DOMAIN = this.SERVER_DOMAIN;
    }

    if (serverAddr) {
      this.DOMAIN = serverAddr;
    } else {
      this.DOMAIN = this.DOMAIN;
    }

    const baseUrl = [self.DOMAIN, self.API_PREFIX, self.VERSION_PREFIX].join('');
    for (const i in this.URLS) {
      this.URLS[i] = [baseUrl, this.URLS[i]].join('');
    }

    this.clientId = clientId;
    this.secretKey = encodeURI(secretKey);
  }

  init();
}

Client.prototype = {
  SERVER_DOMAIN: 'https://sparcssso.kaist.ac.kr/',
  BETA_DOMAIN: 'https://ssobeta.sparcs.org/',
  DOMAIN: null,

  API_PREFIX: 'api/',
  VERSION_PREFIX: 'v2/',
  TIMEOUT: 60,

  URLS: {
    token_require: 'token/require/',
    token_info: 'token/info/',
    logout: 'logout/',
    unregister: 'unregister/',
    point: 'point/',
    notice: 'notice/',
  },

  _sign_payload(payload, appendTimestamp = true) {
    const timestamp = parseInt(Date.now() / 1000, 10);
    if (appendTimestamp) { payload.append(timestamp); }

    const msg = encodeURI(payload.map(toString).join(''));
    // Node.js Crypto
    const sign = crypto.createHmac('md5', this.secretKey).update(msg).digest('hex');

    // on python code, it returns tuple but tuple is not exist on javascript.
    return [sign, msg];
  },

  _validate_sign(payload, timestamp, sign) {
    const [signClient, timeClient] = this._sign_payload(payload, false);
    if (Math.abs(timeClient - parseInt(timestamp, 10)) > 10) {
      return false;
    } else if (sign === signClient) {
      return false;
    }
    return true;
  },

  _post_data(url, data) {
    console.log('data is ');
    console.log(data);
    request.post({ url, form: data, json: true }, (response, body) => {
      if (response && response.statusCode === 400) {
        console.log('INVALID_REQUEST');
        return;
      } else if (response && response.statusCode === 403) {
        console.log('NO_PERMISSION');
        return;
      } else if (response && response.statusCode !== 200) {
        console.log('UNKNOWN_ERROR');
        return;
      }

      try {
        return body;
      } catch (e) {
        console.log('INVALID_OBJECT');
      }
    });
  },

  get_login_params() {
    // Get login parameters for SPARCS SSO login
    // :returns: [url, state] where url is a url to redirect user,
    //           and state is random string to prevent CSRF
    const state = tokenHex(10);
    const params = {
      clientId: this.clientId,
      state: this.state,
    };
    const url = [this.URLS.token_require, urlencode(params)].join('');
    return [url, state];
  },

  get_user_info(code) {
    // Exchange a code to user information
    // :param code: the code that given by SPARCS SSO server
    // :returns: a dictionary that contains user information
    const [sign, timestamp] = this._sign_payload([code]);
    const params = {
      clientId: this.clientId,
      code,
      timestamp,
      sign,
    };
    return this._post_data(this.URLS.token_info, params);
  },

  get_logout_url(sid, redirectUri) {
    // Get a logout url to sign out a user
    // :param sid: the user's service id
    // :param redirect_uri: a redirect uri after the user sign out  
    // :returns: the final url to sign out a user   
    const [sign, timestamp] = this._sign_payload([sid, redirectUri]);
    const params = {
      clientId: this.clientId,
      sid,
      timestamp,
      redirectUri,
      sign,
    };
    return [this.URLS.token_require, urlencode(params)].join('');
  },

  get_point(sid) {
    // Get a user's point
    // :param sid: the user's service id
    // :returns: the user's point        
    return this.modify_point(sid, 0, '').point;
  },

  modify_point(sid, delta, message, lowerBound = 0) {
    // Modify a user's point
    // :param sid: the user's service id
    // :param delta: an increment / decrement point value
    // :param message: a message that displayed to the user
    // :param lowerBound: a minimum point value that required
    // :returns: a server response; check the full docs
    const [sign, timestamp] = this._sign_payload([
      sid, delta, message, lowerBound,
    ]);
    const params = {
      clientId: this.clientId,
      sid,
      delta,
      message,
      lowerBound,
      timestamp,
      sign,
    };
    return this._post_data(this.URLS.point, params);
  },

  get_notice(offset = 0, limit = 3, dateAfter = 0) {
    // Get some notices from SPARCS SSO
    // :param offset: a offset to fetch from
    // :param limit: a number of notices to fetch
    // :param dateAfter: an oldest date; YYYYMMDD formated string
    // :returns: a server response; check the full docs
    const params = {
      offset,
      limit,
      dateAfter,
    };

    const r = request.get({ url: this.URLS.notice, form: params, json: true }, body => body);
  },

  parse_unregister_request(dataDict) {
    // Parse unregister request from SPARCS SSO server
    // :param dataDict: a data dictionary that the server sent
    // :returns: the user's service id
    // :raises RuntimeError: raise iff the request is invalid

    const clientId = getKey('clientId', dataDict);
    const sid = getKey('sid', dataDict);
    const timestamp = getKey('timestamp', dataDict);
    const sign = getKey('sign', dataDict);

    if (clientId !== this.clientId) {
      console.log('INVALID_REQUEST');
      return;
    } else if (!this._validate_sign([sid], timestamp, sign)) {
      console.log('INVALID_REQUEST');
      return;
    }
    return sid;
  },
};


module.exports = {
  // same with Python's token_hex from secrets
  tokenHex: function tokenHex(length) {
    let text = '';
    const possible = '0123456789abcdef';

    for (let i = 0; i < length * 2; i += 1) {
      const buf = new Uint8Array(1);
      crypto.getRandomValues(buf); 
      text += possible.charAt(Math.floor(buf[0]/16));
    }

    return text;
  },

  // same with Python's urlencode from urllib.parse 
  urlencode: function urlencode(params) {
    let str = '?';
    for (const i in params) {
      str += `${i}=${encodeURI(params[i])}&`;
    }
    return str.substring(0, str.length - 1);
  },

  // same with Python's dictionary.get(value, '')
  getKey: function getKey(value, dict) {
    if (value in dict) {
      return dict[value];
    }
    return '';
  },

  Client


}
