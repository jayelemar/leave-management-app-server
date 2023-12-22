const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

const generateToken = id => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    console.log("Request Body:", req.body);

    // Validation
    if (!name || !email || !password) {
        console.log("Validation Error: Please fill in all required fields");
        return res.status(400).json({
            success: false,
            message: "Please fill in all required fields",
            errors: {
                name: !name ? "Name is required" : null,
                email: !email ? "Email is required" : null,
                password: !password ? "Password is required" : null
            }
        });
    }

    if (password.length < 6) {
        console.log("Validation Error: Password must be up to 6 characters");
        return res.status(400).json({
            success: false,
            message: "Password must be up to 6 characters",
            errors: {
                password: "Password must be at least 6 characters long"
            }
        });
    }

    // Check if user email already exists
    const userExist = await User.findOne({ email });
    if (userExist) {
        console.log("Validation Error: Email has already been registered");
        return res.status(400).json({
            success: false,
            message: "Email has already been registered",
            errors: {
                email: "Email has already been registered"
            }
        });
    }
    // Create a new user in the database
    const newUser = new User({
        name,
        email,
        password
    });

    await newUser.save();

    // Generate Token
    const token = generateToken(newUser._id);

    // Send HTTP-only Cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true
    });

    res.status(201).json({
        _id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        token
    });
});

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    console.log("Received Login Request: ", { email, password });
    // validate req
    if (!email && !password) {
        res.status(400);
        throw new Error("Please add email and password");
    }

    //check if user exists
    const user = await User.findOne({ email });
    console.log("Fetched User from DB:", user);

    if (!user) {
        res.status(400);
        throw new Error("User not found, please signup");
    }

    // Log the received email and password
    console.log("Received Email:", email);
    console.log("Received Password:", password);

    // Log the user email and hashed password from the database
    console.log("User Email from DB:", user.email);
    console.log("User Password from DB:", user.password);

    // User exist, check if password is correct
    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    // Generate Token
    const token = generateToken(user._id);

    // Send HTTP-only Cookie
    if (passwordIsCorrect) {
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1day
            sameSite: "none",
            secure: true
        });
        console.log("password is correct: ", password);
    }

    if (user && passwordIsCorrect) {
        const { _id, name, email } = user;
        res.status(200).json({
            _id,
            name,
            email,
            token
        });
    } else {
        console.log("Invalid email or password");
        res.status(400);
        throw new Error("Invalid email or password");
    }
});

const logoutUser = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    // Expire the cookie to logout
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0), // expire now
        sameSite: "none",
        secure: true
    });
    return res.status(200).json({ message: "Successfully Logout" });
});

const getUser = asyncHandler(async (req, res) => {
    if (!req.user || !req.user._id) {
        res.status(400);
        throw new Error("User not found.");
    }

    const userId = req.user._id;

    const user = await User.findById(userId);

    if (!user) {
        res.status(400);
        throw new Error("User not found.");
    }

    // Assuming you want to return user details
    const { _id, name, email } = user;

    res.status(200).json({
        _id,
        name,
        email
    });
});

const loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json(false);
    }

    // Verify Token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if (verified) {
        return res.json(true);
    }
    return res.json(false);
});

const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { name, email } = user;

        (user.email = email), (user.name = req.body.name || name);

        const updatedUser = await user.save();
        res.status(200).json({
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email
        });
    } else {
        res.status(404);
        throw new Error("User not Found");
    }
});

const changePassword = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    const { oldPassword, password } = req.body;
    if (!user) {
        res.status(400);
        throw new Error("User not found, please signup");
    }
    //Validate
    if (!oldPassword || !password) {
        res.status(400);
        throw new Error("Please add old and new password");
    }

    // Check if the old password matches the password in the database
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

    // Save the new password
    if (user && passwordIsCorrect) {
        user.password = password;
        await user.save();
        res.status(200).send("Password change successful");
    } else {
        res.status(400);
        throw new Error("Old password is incorrect");
    }
});

const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        res.status(404).json({ error: "User does not exist" });
        return;
    }

    // Delete Token if it exist in DB
    if (user._id) {
        let token = await Token.findOne({
            userId: user._id
        });
        if (token) {
            await token.deleteOne();
        }
    }

    // Create Reset Token
    let resetToken = crypto.randomBytes(32).toString("hex");

    // Hash token before saving to DB
    const hashedToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    // Save Token to DB
    await new Token({
        userId: user._id,
        token: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 30 * (60 * 1000) //30 mins
    }).save();

    // Construct Reset Url
    const frontendUrl = process.env.FRONTEND_URL || "http://localhost:5173";
    const resetUrl = `${frontendUrl}/resetpassword/${resetToken}`;

    //Reset Email
    const message = `
        <h2>Hello ${user.name}</h2>
        <p>Please use the url below to reset your password.</p>
        <p>This reset link is valid for only 30minutes.</p>
        <a href=${resetUrl} clicktracking=off>${resetUrl}</a>

        <p>Regards</p>
        <p>My Team</p>
    `;
    const subject = "Password Reset Request";
    const send_to = user.email;
    const send_from = process.env.EMAIL_USER;

    try {
        await sendEmail(subject, message, send_to, send_from);
        res.status(200).json({
            success: true,
            message: "Reset Email Sent"
        });
    } catch (error) {
        res.status(500);
        throw new Error("Email not sent, please try again");
    }
});

const resetPassword = asyncHandler(async (req, res) => {
    const { password } = req.body;
    const { resetToken } = req.params;

    // Hash token, then compare to token in DB
    const hashedToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    const userToken = await Token.findOne({
        token: hashedToken,
        expiresAt: { $gt: Date.now() } ////$gt - greater than current time (Date.now)
    });

    if (!userToken) {
        res.status(404);
        throw new Error("Invalid or Expired Token");
    }

    const user = await User.findById(userToken.userId);
    if (!user) {
        res.status(404);
        throw new Error("User not found");
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);

    // Save the updated user
    await user.save();

    // Delete the used reset token
    await userToken.deleteOne();

    res.status(200).json({
        success: true,
        message: "Password reset successful"
    });

    console.log("User Email from Token:", user.email);
    console.log("Updated User Email:", user.email);
    console.log("Updated User Password:", user.password);
});

module.exports = {
    registerUser,
    loginUser,
    logoutUser,
    getUser,
    loginStatus,
    updateUser,
    changePassword,
    forgotPassword,
    resetPassword
};

