const express = require('express');
const session = require('express-session');
const Client = require('./sparcsssov2');

const app = express();

app.use(session({
  key: 'sid',
  resave: false,
  saveUninitialized: true,
  secret: 'secretkey',
  cookie: {
    maxAge: 1000 * 60 * 60, // 쿠키 유효기간 1시간
  },
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
  // console.log(req.session);
  res.send(req.session);
  console.log(req.session);
  return req.session;
});

app.get('/login', (req, res) => {
  const sess = req.session;
  if (Object.prototype.hasOwnProperty.call(sess, 'authenticated') && sess.authenticated === true) {
    return res.redirect(getKey(sess, 'next', '/'));
  }
  const [loginUrl, state] = client.getLoginParams();
  sess.ssoState = state;
  // console.log('sso state is ')
  // console.log(sess.ssoState)
  // console.log(state)
  return res.redirect(loginUrl);
});

app.get('/login/callback', (req, res) => {
  const sess = req.session;
  const stateBefore = getKey(sess, 'ssoState', 'default');

  const state = getKey(req.query, 'state', '');
  // console.log('this state is session from ');
  // console.log(stateBefore);
  // console.log('this state is req.params from ');
  // console.log(state);
  if (stateBefore !== state) {
    throw new Error('State changed');
  }

  const code = getKey(req.query, 'code', '');
  // console.log('this code is req params from ');
  // console.log(code);
  const profile = client.getUserInfo(code)
  sess.authenticated = true;

  let next;

  if (Object.prototype.hasOwnProperty.call(sess, 'next')) {
    next = sess.next;
    delete sess.next;
  } else {
    next = '/';
  }
  return res.redirect(next);
});

app.get('/logout', (req, res) => {
  const sess = req.session;
  if (!sess.authenticated) {
    console.log('REDIRECTED');
    return res.redirect('/');
  }
  const sid = getKey(sess, 'sid', '');
  client.getLogoutUrl(sid, '/');
  return res.redirect('/');
});

const server = app.listen(3000, () => {
  console.log('Express server has started on port 3000');
});
