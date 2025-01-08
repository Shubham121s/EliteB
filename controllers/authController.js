const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const { generateOtp } = require('../utils/generateOtp');
const { sendEmail } = require('../utils/sendEmail');
const { sendSms } = require('../utils/sendSms');
const bcrypt = require('bcrypt');
const ErrorHandler = require('../utils/errorHandler');

// Signup
exports.signup = async (req, res) => {
  const { email, mobile, password } = req.body;
  try {
    const existingUser = await User.findOne({ $or: [{ email }, { mobile }] });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const user = new User({ email, mobile, password });
    await user.save();

    res.status(201).json({ message: 'User registered successfully ' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Login via Email and Password
exports.loginWithEmailPassword = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Verify the password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    // Store the token in an HTTP-only cookie
    res.cookie('token', token, {
      httpOnly: true, // Prevents client-side access to the cookie
      secure: process.env.NODE_ENV === 'production', // Ensures cookies are sent over HTTPS in production
      sameSite: 'strict', // Prevents CSRF attacks
      maxAge: 24 * 60 * 60 * 1000, // 1 day in milliseconds
    });

    // Respond with a success message, user ID, and the token
    res.status(200).json({
      message: 'User successfully logged in 🎉',
      userId: user._id,
      token,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Login via Mobile OTP
exports.loginWithMobileOtp = async (req, res) => {
  const { mobile } = req.body;
  try {
    const user = await User.findOne({ mobile });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const mobileOtp = generateOtp();
    user.mobileOtp = mobileOtp;
    await user.save();

    await sendSms(mobile, `Your OTP is: ${mobileOtp}`);
    res.status(200).json({ message: 'OTP sent to mobile' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Verify Mobile OTP
exports.verifyMobileOtpLogin = async (req, res) => {
  const { mobile, otp } = req.body;
  try {
    const user = await User.findOne({ mobile });
    if (!user || user.mobileOtp !== otp) return res.status(400).json({ message: 'Invalid OTP' });

    user.mobileOtp = null;
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Login via Email OTP
exports.loginWithEmailOtp = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const emailOtp = generateOtp();
    user.emailOtp = emailOtp;
    await user.save();

    await sendEmail(email, 'Your Login OTP', `Your OTP is: ${emailOtp}`);
    res.status(200).json({ message: 'OTP sent to email' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Verify Email OTP
exports.verifyEmailOtpLogin = async (req, res) => {
  const { email, otp } = req.body;

  try {
    // Check if the user exists and OTP matches
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.emailOtp !== otp) return res.status(400).json({ message: 'Invalid OTP' });

    // Clear the OTP after successful verification
    user.emailOtp = null;
    await user.save();

    // Generate a JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });

    // Send success response
    res.status(200).json({
      message: 'OTP verified successfully 🎉. User logged in successfully.',
      userId: user._id,
      token,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


// logout
exports.logout = async (req, res) => {
  try {
    res.clearCookie('token', { path: '/' });
    res.status(200).json({ message: 'Successfully logged out' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error logging out', error: error.message });
  }
};

// change Password
exports.changePassword = async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;

  try {
    // Get the user from the request (user ID added by the 'protect' middleware)
    const user = await User.findById(req.user.id).select('+password');

    if (!user) {
      // If user not found, throw error
      return next(new ErrorHandler('User not found', 404));
    }
    

    // Compare the current password with the stored hash
    const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordMatch) {
      // If passwords don't match, throw error
      return next(new ErrorHandler('Incorrect current password', 401));
    }

    // Validate the new password (optional check)
    if (newPassword.length < 6) {
      // If new password is too short, throw error
      return next(new ErrorHandler('New password must be at least 6 characters long', 400));
    }

    // Hash the new password before saving it
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    user.password = hashedPassword;
    await user.save();

    // Respond with a success message
    res.status(200).json({
      message: 'Your password has been successfully changed. You can now use your new password to log in.',
    });
  } catch (error) {
    // Handle unexpected errors and pass them to the next middleware
    console.error(error);
    return next(error);
  }
};





