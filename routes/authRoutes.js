const express = require('express');
const {
  signup,
  loginWithMobileOtp,
  verifyMobileOtpLogin,
  loginWithEmailOtp,
  verifyEmailOtpLogin,
  logout,
  loginWithEmailPassword,
  changePassword,
 
} = require('../controllers/authController');
const{protect} = require('../middlewares/authMiddleware')
const router = express.Router();

router.post('/signup', signup);
router.post('/login-mobile-otp', loginWithMobileOtp);
router.post('/verify-mobile-login', verifyMobileOtpLogin);
router.post('/login-email-otp', loginWithEmailOtp);
router.post('/verify-email-login', verifyEmailOtpLogin);
router.post('/logout',logout);
router.post('/loginwithEmail-Password',loginWithEmailPassword);
router.post("/changePassword", protect, changePassword);



module.exports = router;
