const { prisma } = require("../prisma/prisma-client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const login = async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email or password are required" });
  }

  const user = await prisma.user.findFirst({
    where: {
      email,
    },
  });

  const isPassswordValid =
    user && (await bcrypt.compare(password, user.password));
  const secret = process.env.JWT_SECRET;

  if (user && isPassswordValid && secret) {
    res.status(200).json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        token: jwt.sign({ userId: user.id }, process.env.JWT_SECRET),
      },
    });
  } else {
    res.status(401).send({ error: "Invalid email or password" });
  }
};

const register = async (req, res, next) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: "Name, email or password are required" });
  }

  const registerUser = await prisma.user.findFirst({
    where: {
      email,
    },
  });

  if (registerUser) {
    return res.status(400).json({ error: "User already exists" });
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const user = await prisma.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
    },
  });

  const secret = process.env.JWT_SECRET;

  if (user && secret) {
    res.status(201).json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        token: jwt.sign({ userId: user.id }, secret, { expiresIn: "1d" }),
      },
    });
  } else {
    res.status(401).send({ error: "Invalid email or password" });
  }
};

const current = (req, res) => {
  return res.status(200).json(req.user);
};

module.exports = { login, register, current };
