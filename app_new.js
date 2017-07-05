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

function loginInit(req, res) {
  const sess = req.session;
  if (Object.prototype.hasOwnProperty.call(sess, 'authenticated') && sess.authenticated === true) {
    return res.redirect(getKey(sess, 'next', '/'));
  }
  const [loginUrl, state] = client.getLoginParams();
  sess.ssoState = state;
  return res.redirect(loginUrl);
}

function loginCallback(req, res) {
  const sess = req.session;
  const stateBefore = getKey(sess, 'ssoState', 'default');

  // 장고에서 request.GET.get(state, '')하는 부분인데, req.params가 정확히 dictionary 형식으로 return해주는지 모르겠음.
  const state = getKey(req.params, 'state', '');

  if (stateBefore !== state) {
    throw new Error('State changed');
  }

  const code = getKey(req.params, 'code', '');
  const profile = client.getUserInfo(code);


  let next;

  if (Object.prototype.hasOwnProperty.call(sess, 'next')) {
    next = sess.next;
    delete sess.next;
  } else {
    next = '/';
  }
  return res.redirect(next);
}

app.get('/', function(req, res) {
  console.log(req.session)
  res.send(req.session)
  return req.session
})

app.get('/login', function (req, res) {
  const sess = req.session;
  if (Object.prototype.hasOwnProperty.call(sess, 'authenticated') && sess.authenticated === true) {
    return res.redirect(getKey(sess, 'next', '/'));
  }
  const [loginUrl, state] = client.getLoginParams();
  sess.ssoState = state;
  return res.redirect(loginUrl);
})

app.get('/login/callback', function (req, res) {
  const sess = req.session;
  const stateBefore = getKey(sess, 'ssoState', 'default');

  // 장고에서 request.GET.get(state, '')하는 부분인데, req.params가 정확히 dictionary 형식으로 return해주는지 모르겠음.
  const state = getKey(req.params, 'state', '');

  if (stateBefore !== state) {
    throw new Error('State changed');
  }

  const code = getKey(req.params, 'code', '');
  const profile = client.getUserInfo(code);


  let next;

  if (Object.prototype.hasOwnProperty.call(sess, 'next')) {
    next = sess.next;
    delete sess.next;
  } else {
    next = '/';
  }
  return res.redirect(next);
})


var server = app.listen(3000, function(){
 console.log("Express server has started on port 3000")
});