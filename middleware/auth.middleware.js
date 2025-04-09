import jwt from "jsonwebtoken";

export const isLoggedIn = async (req, res, next) => {
  try {
    console.log(req.cookies);
    let token = req.cookies?.token;
    console.log("Token found", token ? "Yes" : "No");

    if (!token) {
      console.log("Token not found");
      return res.status(401).json({
        message: "Authentication failed",
        success: false,
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded Data", decoded);
    req.user = decoded;

    next();
  } catch (error) {
    console.log("Auth middleware error", error);
    return res.status(401).json({
      message: "Authentication failed",
      success: false,
    });
  }
};
