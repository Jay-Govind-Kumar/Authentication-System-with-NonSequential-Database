import mongoose from "mongoose";

import dotenv from "dotenv";
dotenv.config();

// export a function that connects to the database

const db = () => {
  mongoose
    .connect(process.env.MONGO_URL)
    .then(() => {
      console.log("Connected to database");
    })
    .catch((err) => {
      console.log("Error in connecting to database");
    });
};

export default db;