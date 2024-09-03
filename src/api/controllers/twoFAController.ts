import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import {TokenContent, User, UserWithLevel} from '@sharedTypes/DBTypes';
import {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import fetchData from '../../utils/fetchData';
import OTPAuth from 'otpauth';
import twoFAModel from '../models/twoFAModel';
import QRCode from 'qrcode';
import jwt from 'jsonwebtoken';

const setupTwoFA = async (
  req: Request<{}, {}, User>,
  res: Response<{qrCodeUrl: string}>,
  next: NextFunction,
) => {
  try {
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    const userResponse = await fetchData<UserResponse>(
      process.env.AUTH_URL + '/api/v1/users',
      options,
    );

    const secret = new OTPAuth.Secret();

    const totp = new OTPAuth.TOTP({
      issuer: 'Derp',
      label: userResponse.user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret,
    });

    await twoFAModel.create({
      userId: userResponse.user.user_id,
      email: userResponse.user.email,
      twoFactorSecret: secret.base32,
      twoFactorEnabled: true,
    });

    const imageUrl = await QRCode.toDataURL(totp.toString());
    res.json({qrCodeUrl: imageUrl});
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

const verifyTwoFA = async (
  req: Request<{}, {}, {email: string; code: string}>,
  res: Response<LoginResponse>,
  next: NextFunction,
) => {
  const {email, code} = req.body;

  try {
    const twoFAData = await twoFAModel.findOne({email});
    if (!twoFAData || !twoFAData.twoFactorEnabled)
      return next(new CustomError('2FA not enabled', 400));

    const totp = new OTPAuth.TOTP({
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(twoFAData.twoFactorSecret),
    });
    const isValid = totp.validate({
      token: code,
      window: 1,
    });

    if (!isValid) return next(new CustomError('Invalid 2FA code', 400));
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({email}),
    };
    const userResponse = await fetchData<UserWithLevel>(
      process.env.AUTH_URL + '/api/v1/users/' + twoFAData.userId,
      options,
    );
    if (!userResponse) return next(new CustomError('User not found', 404));
    // TODO: Create and return a JWT token
    const tokenContent: TokenContent = {
      user_id: userResponse.user_id,
      level_name: userResponse.level_name,
    };
    if (!process.env.JWT_SECRET) throw new Error('missing JWT_SECRET');
    const token = jwt.sign(tokenContent, process.env.JWT_SECRET, {
      expiresIn: '12h',
    });
    res.json({
      token,
      user: userResponse,
      message: 'Logged in',
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {setupTwoFA, verifyTwoFA};
