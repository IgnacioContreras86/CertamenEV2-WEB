import { UserRepository } from '../repositories/user.repository.js';

const userRepository = new UserRepository();

export class AuthController {
  async login(req, res) {
    const { username, password } = req.body;

    const user = await userRepository.login(username, password);

    if (!user) {
      return res.status(401).json({
        error: "Nombre de usuario o contraseña incorrectos"
      });
    }

    res.json({
      username: user.username,
      token: user.token,
      name: user.name
    });
  }

  async logout(req, res) {
    const token = req.get("X-Authorization");
    const success = await userRepository.logout(token);

    if (!success) {
      return res.status(401).json({
        error: "Token inválido"
      });
    }

    res.status(204).end();
  }
} 