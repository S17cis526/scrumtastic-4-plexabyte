module.exports = {
  create: create,
  update: update,
  read: read
}

var json = require('form-json');
var encryption = require('./../lib/encryption');

function create(req, res, db) {
  json(req, res, function(req, res) {
    var user = req.body;
    var salt = encryption.salt();
    var cryptedPassword = encryption.digest(user.password + salt); //digest appends secret
    db.run('INSERT INTO users (eid, email, firstName, lastName, cryptedPassword) VALUES (?, ?, ?, ?, ?)',
          [
            user.eid,
            user.email,
            user.firstName,
            user.lastName,
            cryptedPassword,
            salt
          ], function(err) {
              if (err) {return;}
              res.statusCode(200);
              res.end("User Created");
            })
  });
}

function read(req, res, db) {
  var id = req.parrams.id;
  db.get('SELECT eid, email, firstName, lastName FROM user WHERE user_id=?', [id], function(user) {
    res.setHeader("Content-Type", "text/json");
    res.end(JSON.stringify(user));
  });
}
