import bcrypt from 'bcryptjs';
import * as grpc from '@grpc/grpc-js';
import {
  createUser,
  findUniqueUser,
  findUser,
  signTokens,
} from '../services/user.service';
import { SignUpUserInput__Output } from '../../pb/auth/SignUpUserInput';
import { SignInUserInput__Output } from '../../pb/auth/SignInUserInput';
import { SignInUserResponse__Output } from '../../pb/auth/SignInUserResponse';
import { SignUpUserResponse } from '../../pb/auth/SignUpUserResponse';
import { RefreshTokenInput__Output } from '../../pb/auth/RefreshTokenInput';
import { RefreshTokenResponse } from '../../pb/auth/RefreshTokenResponse';
import { signJwt, verifyJwt } from '../utils/jwt';
import customConfig from '../config/default';
import redisClient from '../utils/connectRedis';

export const registerHandler = async (
  req: grpc.ServerUnaryCall<SignUpUserInput__Output, SignUpUserResponse>,
  res: grpc.sendUnaryData<SignUpUserResponse>
) => {
  try {
    const hashedPassword = await bcrypt.hash(req.request.password, 12);
    const user = await createUser({
      email: req.request.email.toLowerCase(),
      name: req.request.name,
      password: hashedPassword,
      photo: req.request.photo,
      provider: 'local',
    });

    res(null, {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        photo: user.photo!,
        provider: user.provider!,
        role: user.role!,
        created_at: {
          seconds: user.created_at.getTime() / 1000,
        },
        updated_at: {
          seconds: user.updated_at.getTime() / 1000,
        },
      },
    });
  } catch (err: any) {
    if (err.code === 'P2002') {
      res({
        code: grpc.status.ALREADY_EXISTS,
        message: 'Email already exists',
      });
    }
    res({ code: grpc.status.INTERNAL, message: err.message });
  }
};

export const loginHandler = async (
  req: grpc.ServerUnaryCall<
    SignInUserInput__Output,
    SignInUserResponse__Output
  >,
  res: grpc.sendUnaryData<SignInUserResponse__Output>
) => {
  try {
    const user = await findUser({ email: req.request.email });

    if (!user || !(await bcrypt.compare(req.request.password, user.password))) {
      res({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'Invalid email or password',
      });
    }

    const { access_token, refresh_token } = await signTokens(user);

    res(null, {
      status: 'success',
      access_token,
      refresh_token,
    });
  } catch (err: any) {
    res({
      code: grpc.status.INTERNAL,
      message: err.message,
    });
  }
};

export const refreshAccessTokenHandler = async (
  req: grpc.ServerUnaryCall<RefreshTokenInput__Output, RefreshTokenResponse>,
  res: grpc.sendUnaryData<RefreshTokenResponse>
) => {
  try {
    const refresh_token = req.request.refresh_token as string;

    const message = 'Could not refresh access token';
    if (!refresh_token) {
      res({
        code: grpc.status.PERMISSION_DENIED,
        message,
      });
    }

    const decoded = verifyJwt<{ sub: string }>(
      refresh_token,
      'refreshTokenPublicKey'
    );

    if (!decoded) {
      res({
        code: grpc.status.PERMISSION_DENIED,
        message,
      });
      return;
    }

    const session = await redisClient.get(decoded?.sub);
    if (!session) {
      res({
        code: grpc.status.PERMISSION_DENIED,
        message,
      });
      return;
    }

    const user = await findUniqueUser({ id: JSON.parse(session).id });

    if (!user) {
      res({
        code: grpc.status.PERMISSION_DENIED,
        message,
      });
    }

    const access_token = signJwt({ sub: user.id }, 'accessTokenPrivateKey', {
      expiresIn: `${customConfig.accessTokenExpiresIn}m`,
    });

    res(null, { access_token, refresh_token });
  } catch (err: any) {
    res({
      code: grpc.status.INTERNAL,
      message: err.message,
    });
  }
};