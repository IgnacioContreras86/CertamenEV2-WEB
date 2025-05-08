import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const authMiddleware = async (req, res, next) => {
  const token = req.get("X-Authorization");

  if (!token) {
    return res.status(401).json({
      error: "No se ha proporcionado un token de autorización",
    });
  }

  const user = await prisma.user.findFirst({
    where: { token }
  });

  if (!user) {
    return res.status(401).json({
      error: "El token es inválido"
    });
  }

  req.user = user;
  next();
}; 