const isAdmin = (req, res, next) => {
   // Check if the user is authenticated
   if (!req.user) {
      return res
         .status(401)
         .json({ message: 'You must be logged in to access this resource' });
   }

   // Check if the user has the "admin" permission
   if (req.user.permissions.includes('chef')) {
      return next();
   } else {
      return res.status(403).json({
         message: 'You do not have permission to access this resource'
      });
   }
};
module.exports = isAdmin;
