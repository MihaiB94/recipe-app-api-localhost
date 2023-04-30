const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Token = require('../models/Token');

const AuthToken = (requiredPermissions) => async (req, res, next) => {
   const authHeader = req.headers.authorization;
   const token = authHeader && authHeader.split(' ')[1];

   if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
   }

   try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
      const userId = decoded.id;

      // Check if token exists in database
      const tokenExists = await Token.exists({ userId, token });

      if (!tokenExists) {
         return res.status(401).json({
            message: 'Unauthorized! You do not have access to this page! '
         });
      }

      // Get user from database
      const user = await User.findById(userId);

      if (!user) {
         return res.status(401).json({ message: 'Unauthorized' });
      }

      // Check user's permissions against required permissions
      const hasRequiredPermissions = requiredPermissions.every((permission) =>
         user.permissions.includes(permission)
      );
      if (!hasRequiredPermissions) {
         return res.status(403).json({
            message:
               'You cannot add new recipes. Contact the admin to request the permissions!'
         });
      }

      // Check if token has expired
      if (decoded.exp < Date.now() / 1000) {
         return res
            .status(401)
            .json({ message: 'Unauthorized - token has expired' });
      }

      // Add user object to request
      req.user = {
         id: user._id,
         username: user.username,
         favorites: user.favorites,
         confirmationToken: user.confirmationToken
      };

      next();
   } catch (error) {
      return res.status(401).json({ message: 'Unauthorized' });
   }
};

module.exports = AuthToken;
