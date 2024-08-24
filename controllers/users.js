const { prisma } = require("../prisma/prisma-client");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const login = async (req, res) => {
  try {
    const { name, password } = req.body;

    if (!name || !password) {
      return res
        .status(400)
        .json({ message: "Пожалуйста, заполните обязятельные поля" });
    }

    const user = await prisma.user.findFirst({
      where: {
        name,
      },
    });

    const isPassswordValid =
      user && (await bcrypt.compare(password, user.password));
    const secret = process.env.JWT_SECRET;

    if (user && isPassswordValid && secret) {
      res.status(200).json({
        id: user.id,
        email: user.email,
        name: user.name,
        token: jwt.sign({ userId: user.id }, secret, { expiresIn: "30d" }),
      });
    } else {
      res.status(401).send({ message: "Неверно введен логин или пароль" });
    }
  } catch {
    res.status(500).json({ message: "Что-то пошло не так" });
  }
};

const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ message: "Пожалуйста, заполните обязательные поля" });
    }

    const registerUser = await prisma.user.findFirst({
      where: {
        email,
      },
    });

    if (registerUser) {
      return res
        .status(400)
        .json({ message: "Пользователь, с таким email уже существует" });
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
        id: user.id,
        email: user.email,
        name: user.name,
        token: jwt.sign({ userId: user.id }, secret, { expiresIn: "30d" }),
      });
    } else {
      res.status(401).send({ message: "Не удалось создать пользователя" });
    }
  } catch {
    res.status(500).json({ message: "Что-то пошло не так" });
  }
};

const current = (req, res) => {
  return res.status(200).json(req.user);
};

module.exports = { login, register, current };
