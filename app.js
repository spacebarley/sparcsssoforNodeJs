const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);
const Client = require('./sparcsssov2');
const request = require('request');
const app = express();

app.use(session({
    secret: '4a68305ccb64c7b944bc',
    resave: false,
    store: new MongoStore(options)
}));

var client = new Client('teste0b822cdafbe', '4a68305ccb64c7b944bc', true);

function login_init(req){
  session = req.session
  if (req.user.is_authenticated()){
    session.next = '/'
    res.redirect(session.next);
  }

  let [login_url, state] = client.get_login_params()
  session.state = state
  
  return res.redirect(login_url)
}

app.get('/', function(req, res){
    sess = req.session
    console.log(storage)
    res.send({
        'account': storage['account'],
        'loggedin': storage['loggedin'],
        'unregister': {
            'accept': '/unregister/accept',
            'deny': '/unregister/deny',
        },
        'urls': {
            'login': '/login',
            'logout': '/logout',
            'point-get': '/point/get',
            'point-modify': '/point/modify?delta=1000',
        },
        'domain':storage['client'].DOMAIN})
});

app.get('/login', function(req, res){
    res.send('Login please')
})





app.listen(3000, function(){
    console.log('Connected 3000 port!');
});