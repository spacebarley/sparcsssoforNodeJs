const express = require('express');
const session = require('express-session');
const Client = require('./sparcsssov2');
// const MongoStore = require('connect-mongo')(session);

const app = express();


app.use(session({
  key: 'destroyKey',
  resave: false,
  saveUninitialized: true,
  secret: 'secretkey',
  cookie: {
    maxAge: 1000 * 60 * 60, // 쿠키 유효기간 1시간
  },
  // store: new MongoStore(options),
}));

const client = new Client('teste0b822cdafbe', '4a68305ccb64c7b944bc', false);


// Javascript have no function for set default value.
function getKey(dict, key, replacement) {
  if (Object.prototype.hasOwnProperty.call(dict, key)) {
    return dict[key];
  }
  return replacement;
}
app.get('/', (req, res) => {
  res.send(req.session);
  return req.session;
});

app.get('/login', (req, res) => {
  const sess = req.session;
  if (Object.prototype.hasOwnProperty.call(sess, 'authenticated') && sess.authenticated === true) {
    return res.redirect(getKey(sess, 'next', '/'));
  }
  const [loginUrl, state] = client.getLoginParams();
  sess.ssoState = state;
  return res.redirect(loginUrl);
});

app.get('/login/callback', (req, res) => {
  const sess = req.session;
  const stateBefore = getKey(sess, 'ssoState', 'default');

  const state = getKey(req.query, 'state', '');
  if (stateBefore !== state) {
    throw new Error('State changed');
  }

  const code = getKey(req.query, 'code', '');

  client.getUserInfo(code)
          .then((resp) => {
            sess.authenticated = true;
            sess.sid = resp.sid;
            if (resp.sparcs_id) {
              sess.sparcsId = resp.sparcs_id;
              sess.isSPARCS = true;
            } else {
              sess.isSPARCS = false;
            }
            console.log('=========================');
            console.log(resp);
            console.log('=========================');
            console.log(sess);

            let next;
            if (Object.prototype.hasOwnProperty.call(sess, 'next')) {
              next = sess.next;
              delete sess.next;
            } else {
              next = '/';
            }
            return res.redirect(next);
          });
});

app.get('/logout', (req, res) => {
  const sess = req.session;
  if (!sess.authenticated) {
    console.log('REDIRECTED');
    return res.redirect('/');
  }
  const sid = getKey(sess, 'sid', '');
  client.getLogoutUrl(sid, '/');
  req.session.destroy();
  res.clearCookie('destroyKey');
  return res.redirect('/');
});

const server = app.listen(3000, () => {
  console.log('Express server has started on port 3000');
});
