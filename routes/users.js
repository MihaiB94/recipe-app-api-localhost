const router = require('express').Router();
const User = require('../models/User');
const AuthToken = require('./authToken');

// Library for encrypting passwords saved in the database
const bcrypt = require('bcrypt');

// UPDATE user information
router.put('/:id', AuthToken, async (req, res) => {
   if (req.body.userId === req.params.id) {
      if (req.body.password) {
         const salt = await bcrypt.genSalt(15);
         req.body.password = await bcrypt.hash(req.body.password, salt);
      }
      try {
         const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            {
               $set: req.body
            },
            { new: true }
         );
         res.status(200).json(updatedUser);
      } catch (err) {
         res.status(500).json(err);
      }
   } else {
      res.status(401).json('You do not have acces to this account!');
   }
});

// UPDATE user password
router.put('/:id/password', AuthToken, async (req, res) => {
   if (req.body.userId === req.params.id) {
      try {
         const user = await User.findById(req.params.id);
         const isPasswordValid = await bcrypt.compare(
            req.body.oldPassword,
            user.password
         );
         if (!isPasswordValid) {
            return res.status(401).json('Invalid old password!');
         }
         const salt = await bcrypt.genSalt(15);
         const newPassword = await bcrypt.hash(req.body.newPassword, salt);
         const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            {
               $set: { password: newPassword }
            },
            { new: true }
         );
         res.status(200).json(updatedUser);
      } catch (err) {
         res.status(500).json(err);
      }
   } else {
      res.status(401).json('You do not have access to this account!');
   }
});

// DELETE user information
router.delete('/:id', AuthToken, async (req, res) => {
   if (req.body.userId === req.params.id) {
      try {
         const user = await User.findById(req.params.id);
         if (user) {
            try {
               await User.findByIdAndDelete(req.params.id);
               res.status(200).json('User deleted');
            } catch (error) {
               res.status(500).json(error);
            }
         } else {
            res.status(404).json('User not found');
         }
      } catch (error) {
         res.status(500).json(error);
      }
   } else {
      res.status(401).json('You cannot delete this account!');
   }
});

//GET User
router.get('/:id', AuthToken, async (req, res) => {
   try {
      const user = await User.findById(req.params.id);
      const { password, ...others } = user._doc;
      res.status(200).json(others);
   } catch (err) {
      res.status(500).json(err);
   }
});

//ADD TO FAVORITES
// Add recipes to favorites
router.put('/:userId/favorites/:recipeId', AuthToken, (req, res) => {
   User.findById(req.params.userId)
      .then((user) => {
         if (user) {
            if (!user.favorites.includes(req.params.recipeId)) {
               user.favorites.push(req.params.recipeId);
            } else {
               return res.status(400).json({
                  message: 'Recipe already in favorites'
               });
            }
            return user.save();
         } else {
            res.status(404).json({ message: 'User not found' });
         }
      })
      .then((user) => {
         res.json({
            message: 'Recipe added to favorites',
            favorites: user.favorites
         });
      })
      .catch((err) => {
         res.status(500).json({ message: err.message });
      });
});

// Remove recipes from favorites
router.delete('/:userId/favorites/:recipeId', AuthToken, (req, res) => {
   User.findById(req.params.userId)
      .then((user) => {
         if (user) {
            user.favorites = user.favorites.filter(
               (favoriteId) => favoriteId.toString() !== req.params.recipeId
            );
            return user.save();
         } else {
            res.status(404).json({ message: 'User not found' });
         }
      })
      .then((user) => {
         res.json({
            message: 'Recipe removed from favorites',
            favorites: user.favorites
         });
      })
      .catch((err) => {
         res.status(500).json({ message: err.message });
      });
});

// Get all favorites recipes
router.get('/:userId/favorites', AuthToken, async (req, res) => {
   try {
      const user = await User.findById(req.params.userId).populate('favorites');
      if (!user) {
         return res.status(404).json({ message: 'User not found' });
      }
      res.json(user.favorites);
   } catch (err) {
      res.status(500).json({ message: err.message });
   }
});
module.exports = router;
