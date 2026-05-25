// checks that a user is loggen in or not by using accesstoken if token if provided and correct then user is logged in other wise user is not logged in

import jwt from 'jsonwebtoken';
import { ApiError } from '../utils/ApiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import {User} from '../models/User.model.js';


    
    export const verifyJWT = asyncHandler(async (req, res, next) => {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "");
    
        if (!token) {
          throw new ApiError(401, "Unauthorized request");
    
        }
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken");
        if (!user) {
          throw new ApiError(404, "User not found");
        }
    
        req.user = user;
        next();
      })

