/** @module session
 * a moduele representing a user session
 */

module.exports = {
  create: create,
  destroy: destroy
};

var json = require('../lib/form-json');

/** @function create
 * creates a new session
 */

 function create(req, res) {
   json(req, res, function(req, res) {
     var username = req.body.username;
     var password = req.body.password;
     db.get("SELECT * FROM users WHERE username=?", [username], function(err, user) {
       if(err) {
         console.error(err);
         res.statusCode = 500;
         res.end("Server error");
         return;
       }
       if(!user) {
         //username not in database
         res.statusCode = 403;
         res.end("Incorrect username/password");
         return;
       }
       var cryptedPassword = encryption.digest(password + user.salt);
       if (cryptedPassword != user.cryptedPassword) {
         //invalid password
         res.end("Incorrect username/password");
         return;
       }
       else {
         //successful login
         var cookieData = JSON.stringify({userId: user.id});
         var encryptedCookieData = encryption.encipher(cookieData);

         //Encrypt user_id
         res.setHeader("Set-Cookie", ["session=" + encryptedCookieData]);
         res.statusCode = 200;
         res.end();

       }
     });
   });
 }

 function destroy (req, res) {
   res.setHeader("Set-Cookie", "");
   res.statusCode = 200;
   res.end("Logged out succesfully");
 }

 function loginRequired(req, res, next) {
   var session = req.headers.cookie.session;
   var sessionData = encryption.decipher(session);
   var sessionObj = JSON.parse(sessionData);
   if(sessionObj.userId) {
     req.userId = sessionObj.userId;
     return next(req, res);
   }
   else {
     res.statusCode = 403;
     res.end("Authentication required");
   }
 }
