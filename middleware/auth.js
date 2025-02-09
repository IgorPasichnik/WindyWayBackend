const { prisma } = require("../prisma/prisma-client");
const jwt = require("jsonwebtoken");

const auth = async (req, res, next) => {
  try {
    let token = req.headers.authorization?.split(" ")[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await prisma.user.findUnique({
      where: {
        id: decoded.userId,
      },
    });

    req.user = user;

    next();
  } catch (e) {
    res.status(401).json({ message: "Не существует" });
  }
};

module.exports = { auth };
