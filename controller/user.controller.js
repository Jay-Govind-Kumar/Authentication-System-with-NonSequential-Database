import User from "../model/User.model.js";
import crypto from "crypto";
import nodemailer from "nodemailer";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const registerUser = async (req, res) => {
  // get data
  // validate
  // check if user already exists
  // create a user in database
  // create a verification token
  // save token in database
  // send verification token as email to user
  // send success response

  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({
      message: "All fields are required",
    });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        message: "User already exists",
      });
    }

    const user = await User.create({
      name,
      email,
      password,
    });
    console.log(user);

    if (!user) {
      return res.status(400).json({
        message: "User not registered",
      });
    }

    const token = crypto.randomBytes(32).toString("hex");
    user.verificationToken = token;

    await user.save();

    // send email
    const transporter = nodemailer.createTransport({
      host: process.env.MAILTRAP_HOST,
      port: process.env.MAILTRAP_PORT,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.MAILTRAP_USER,
        pass: process.env.MAILTRAP_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.MAILTRAP_SENDEREMAIL,
      to: user.email,
      subject: "Account Verification",
      text: `Please click on the following link to verify your account: 
      ${process.env.BASE_URL}/api/v1/users/verify/${token}`,
      html: `<p>Please click on the following link to verify your account:
      <a href="${process.env.BASE_URL}/api/v1/users/verify/${token}">Verify Account</a></p>`,
    };

    await transporter.sendMail(mailOptions);

    return res.status(201).json({
      message: "User registered successfully",
      success: true,
    });
  } catch (error) {
    res.status(400).json({
      message: "User not registered",
      error,
      success: false,
    });
  }
};

const verifyUser = async (req, res) => {
  // get token from url
  // validate token
  // find user by token
  // if not
  //set isVerified to true
  // remove verification token from database
  // save
  // return success response

  const { token } = req.params;
  if (!token) {
    return res.status(400).json({
      message: "Invalid token",
    });
  }

  const user = await User.findOne({ verificationToken: token });

  if (!user) {
    return res.status(400).json({
      message: "Invalid token",
    });
  }

  user.isVerified = true;
  user.verificationToken = undefined;
  await user.save();

  return res.status(200).json({
    message: "User verified successfully",
  });
};

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "All fields are required",
    });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({
        message: "Invalid credentials",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({
        message: "Invalid credentials",
      });
    }

    if (!user.isVerified) {
      return res.status(400).json({
        message: "User not verified",
      });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },

      process.env.JWT_SECRET,
      {
        expiresIn: "24h",
      }
    );

    const cookieOptions = {
      httpOnly: true,
      secure: true,
      maxAge: 24 * 60 * 60 * 1000,
    };
    res.cookie("token", token, { cookieOptions });

    return res.status(200).json({
      message: "User logged in successfully",
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    res.status(400).json({
      message: "User not logged in",
      error,
      success: false,
    });
  }
};

const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    console.log(user);

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User not found",
      });
    }

    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      message: "User not found",
      error,
    });
  }
};

const logoutUser = async (req, res) => {
  try {
    res.cookie("token", "", {
      expires: new Date(0),
    });

    res.status(200).json({
      message: "User logged out successfully",
      success: true,
    });
  } catch (error) {
    res.status(400).json({
      message: "User not logged out",
      error,
      success: false,
    });
  }
};

const forgotPassword = async (req, res) => {
  try {
    // get email from request body
    // check if user exists with that email
    // generate reset token + reset token expiry
    // user.save()
    // send email with reset token
    // send success response
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    try {
      const existingUser = await User.findOne({ email });
      if (!existingUser) {
        return res.status(400).json({
          message: "User not found",
        });
      }

      // generate reset token + reset token expiry
      const token = crypto.randomBytes(32).toString("hex");
      existingUser.resetPasswordToken = token;
      existingUser.resetPasswordExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

      await existingUser.save();

      // send email with reset token
      const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_HOST,
        port: process.env.MAILTRAP_PORT,
        secure: false, // true for 465, false for other ports
        auth: {
          user: process.env.MAILTRAP_USER,
          pass: process.env.MAILTRAP_PASSWORD,
        },
      });
      const mailOptions = {
        from: process.env.MAILTRAP_SENDEREMAIL,
        to: existingUser.email,
        subject: "Password Reset",
        text: `Please click on the following link to reset your password: 
        ${process.env.BASE_URL}/api/v1/users/reset-password/${token}`,
        // html: `<p>Please click on the following link to reset your password:
        // <a href="${process.env.BASE_URL}/api/v1/users/reset-password/${token}">Reset Password</a></p>`,
      };

      await transporter.sendMail(mailOptions);

      return res.status(200).json({
        message: "Password reset email sent successfully",
        success: true,
      });
    } catch (error) {
      return res.status(400).json({
        message: "User not found",
      });
    }
  } catch (error) {
    return res.status(400).json({
      message: "User not found",
      error,
    });
  }
};

const resetPassword = async (req, res) => {
  try {
    // collect token from params
    // collect password from request body
    // check if token is valid
    // set password in user
    // remove reset token and expiry from user
    // send success response

    const { token } = req.params;
    const { password, confirmPassword } = req.body;
    if (!token) {
      return res.status(400).json({
        message: "Invalid token",
      });
    }
    if (!password || !confirmPassword) {
      return res.status(400).json({
        message: "All fields are required",
      });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({
        message: "Passwords do not match",
      });
    }

    try {
      const user = await User.findOne({
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() },
      });

      if (!user) {
        return res.status(400).json({
          message: "Invalid token",
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      return res.status(200).json({
        message: "Password reset successfully",
        success: true,
      });
    } catch (error) {
      return res.status(400).json({
        message: "User not found",
      });
    }
  } catch (error) {
    return res.status(400).json({
      message: "User not found",
      error,
    });
  }
};

export {
  registerUser,
  verifyUser,
  login,
  getMe,
  logoutUser,
  forgotPassword,
  resetPassword,
};
