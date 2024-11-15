const knex = require("../database.js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const resolvers = {
  Query: {
    async getUserByJWT(_, _a, { user }) {
      console.log("check user ", user);
      console.log("check user id", user.id);
      if (!user) {
        throw new Error("Unauthorized access: user ID is required.");
      }
      if (user) {
        try {
          const data = await knex("users").where({ id: user.id }).first();
          return data;
        } catch (error) {
          throw new Error(error.message);
        }
      }
    },
    async Login(_, { input }) {
      try {
        const { email, password } = input;
        const dbData = await knex("users").where({ email: email }).first();
        if (dbData.length === 0) {
          throw new Error("No user found");
        }
        const isValidPassword = await bcrypt.compare(
          password,
          dbData["password"]
        );
        if (!isValidPassword) {
          throw new Error("Invalid password");
        }
        const token = jwt.sign({ id: dbData["id"] }, process.env.SECRET);
        return { jwt: token };
      } catch (error) {
        throw new Error(error.message);
      }
    },
  },
  Mutation: {
    async registration(_, { input }) {
      try {
        const { name, email, password } = input;
        const hashedPassword = await bcrypt.hash(password, 10);
        const [dbData] = await knex("users")
          .insert({
            name: name,
            email: email,
            password: hashedPassword,
          })
          .returning("*");
        return dbData;
      } catch (error) {
        throw new Error(error.message);
      }
    },
  },
};

module.exports = resolvers;
