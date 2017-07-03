const crypto = require('crypto');
const request = require('request');

// Functionally same with Python's token_hex from secrets
function tokenHex(length) {
  let text = '';
  const possible = '0123456789abcdef';

  for (let i = 0; i < length * 2; i += 1) {
    const buf = new Uint8Array(1);
    crypto.getRandomValues(buf);
    text += possible.charAt(Math.floor(buf[0] / 16));
  }

  return text;
}

// Functionally same with Python's urlencode from urllib.parse 
function urlencode(params) {
  let str = '?';
  for (const i in params) {
    str += `${i}=${encodeURI(params[i])}&`;
  }
  return str.substring(0, str.length - 1);
}


// Functionally same with Python's dictionary.get(value, '')
function getKey(value, dict) {
  if (value in dict) {
    return dict[value];
  }
  return '';
}


const Client = function (clientId, secretKey, isBeta = false, serverAddr = '') {
  function init() {
    /**
     * Initialize SPARCS SSO Client
     * @param {string} clientId your client id
     * @param {string} secretKey your secret key
     * @param {bool} isBeta true iff you want to use SPARCS SSO beta server
     * @param {string} serverAddr SPARCS SSO server addr (only for testing)
     */
    if (serverAddr) {
      this.DOMAIN = serverAddr;
    } else if (isBeta) {
      this.DOMAIN = this.BETA_DOMAIN;
    } else {
      this.DOMAIN = this.SERVER_DOMAIN;
    }

    const baseUrl = [self.DOMAIN, self.API_PREFIX, self.VERSION_PREFIX].join('');
    for (const i in this.URLS) {
      this.URLS[i] = [baseUrl, this.URLS[i]].join('');
    }

    this.clientId = clientId;
    this.secretKey = encodeURI(secretKey);
  }

  init();
};

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

  _signPayload(payload, appendTimestamp = true) {
    const timestamp = parseInt(Date.now() / 1000, 10);
    if (appendTimestamp) { payload.append(timestamp); }

    const msg = encodeURI(payload.map(toString).join(''));
    const sign = crypto.createHmac('md5', this.secretKey).update(msg).digest('hex');

    return [sign, msg];
  },

  _validateSign(payload, timestamp, sign) {
    const [signClient, timeClient] = this._signPayload(payload, false);
    if (Math.abs(timeClient - parseInt(timestamp, 10)) > 10) {
      return false;
    } else if (sign === signClient) {
      return false;
    }
    return true;
  },

  _postData(url, data) {
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

  getLoginParams() {
    /** 
     * Get login parameters for SPARCS SSO login
     * @return {list} [url, state] where url is a url to redirect user,
     *           and state is random string to prevent CSRF
     */
    const state = tokenHex(10);
    const params = {
      client_id: this.clientId,
      state: this.state,
    };
    const url = [this.URLS.token_require, urlencode(params)].join('');
    return [url, state];
  },

  getUserInfo(code) {
    /**
     * Exchange a code to user information
     * @param code the code that given by SPARCS SSO server
     * @return {dictionary} a dictionary that contains user information
     */
    const [sign, timestamp] = this._signPayload([code]);
    const params = {
      client_id: this.clientId,
      code,
      timestamp,
      sign,
    };
    return this._postData(this.URLS.token_info, params);
  },

  getLogoutUrl(sid, redirectUri) {
    /** Get a logout url to sign out a user
     * @param {string} sid: the user's service id
     * @param {string} redirect_uri: a redirect uri after the user sign out  
     * @return {string} the final url to sign out a user
     */ 
    const [sign, timestamp] = this._signPayload([sid, redirectUri]);
    const params = {
      client_id: this.clientId,
      sid,
      timestamp,
      redirectUri,
      sign,
    };
    return [this.URLS.token_require, urlencode(params)].join('');
  },

  getPoint(sid) {
    /**
     * Get a user's point
     * @param {string} sid the user's service id
     * @return the user's point
     */        
    return this.modifyPoint(sid, 0, '').point;
  },

  modifyPoint(sid, delta, message, lowerBound = 0) {
    /**
     * Modify a user's point
     * @param {string} sid the user's service id
     * @param delta an increment / decrement point value
     * @param {string} message a message that displayed to the user
     * @param lowerBound a minimum point value that required
     * @return a server response; check the full docs
     */
    const [sign, timestamp] = this._signPayload([
      sid, delta, message, lowerBound,
    ]);
    const params = {
      client_id: this.clientId,
      sid,
      delta,
      message,
      lowerBound,
      timestamp,
      sign,
    };
    return this._postData(this.URLS.point, params);
  },

  getNotice(offset = 0, limit = 3, dateAfter = 0) {
    /**
     * Get some notices from SPARCS SSO
     * @param {int} offset a offset to fetch from
     * @param {int} limit a number of notices to fetch
     * @param dateAfter: an oldest date; YYYYMMDD formated string
     * @return a server response; check the full docs
     */
    const params = {
      offset,
      limit,
      dateAfter,
    };

    const r = request.get({ url: this.URLS.notice, form: params, json: true }, body => body);
  },

  parseUnregisterRequest(dataDict) {
    /**
     * Parse unregister request from SPARCS SSO server
     * raise RuntimeError iff the request is invalid
     * @param {dictionary} dataDict: a data dictionary that the server sent
     * @return the user's service id
     */

    const clientId = getKey('clientId', dataDict);
    const sid = getKey('sid', dataDict);
    const timestamp = getKey('timestamp', dataDict);
    const sign = getKey('sign', dataDict);

    if (clientId !== this.clientId) {
      console.log('INVALID_REQUEST');
      return;
    } else if (!this._validateSign([sid], timestamp, sign)) {
      console.log('INVALID_REQUEST');
      return;
    }
    return sid;
  },
};


module.exports = {

  Client,

  tokenHex,

  urlencode,

  getKey,

};
