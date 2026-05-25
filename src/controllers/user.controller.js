import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/fileApload.js"
import { Apiresponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessandRefreshToken= async(userId)=>{
  try {
    const user= await User.findById(userId)
    const accessToken= await user.generateAccessToken()
    const refreshToken= await user.generateRefreshToken()

    user.refreshToken=refreshToken
   await user.save({validateBeforeSave:false})
    return {accessToken,refreshToken}

    
  } catch (error) {
    throw new ApiError(500,"Something went wrong while generating tokens")
  }
}



const registerUser=asyncHandler(async(req,res)=>{
   // get user details from frontend
   // validation - not empty
   // check if user already exists: username,email
   // check for images, check for avatar
   // upload them to cloudinary, avatar
   // create user object - create entry in db
   // remove password and refresh token from resppnse
   // check for user creation
   // return response

   const { fullName ,username, email, password } = req.body;

   console.log("email:", email);

  if(
     [fullName,email,username,password].some((field)=>
      field?.trim()===""
     )
    )
  {
    throw new ApiError(400,"All fields are required")
  }
  const existedUser=await User.findOne({
    $or:[{username},{email}]
  })

  if(existedUser){
    throw new ApiError(409,"User with email or username already exists")
  }
  //console.log("FILES:", req.files);
  const avatarLocalPath = req.files?.avatar?.[0]?.path;
  const coverImageLocalPath = req.files?.coverImage?.[0]?.path;

  if(!avatarLocalPath){
    throw new ApiError(400,"Avatar file is required")
  }
//console.log("FILES:", req.files);
//console.log("AVATAR PATH:", avatarLocalPath);
//console.log("COVER PATH:", coverImageLocalPath);
 const avatar= await uploadOnCloudinary(avatarLocalPath)
 const coverImage= await uploadOnCloudinary(coverImageLocalPath)
 
 if(!avatar){
    throw new ApiError(500,"Failed to upload avatar")
 }

 const user= await User.create({
    fullName,
    avatar:avatar.url,
    coverImage:coverImage?.url || "",
    email,
    username: username.toLowerCase(),
    password
 })

 const createdUser= await User.findById(user._id).select("-password -refreshToken")

  if(!createdUser){
    throw new ApiError(500,"Failed to create user")
  }

  return res.status(201).json(new Apiresponse(201,createdUser,"User registered successfully"))

});
const loginUser=asyncHandler(async(req,res)=>{
    // req.body - data
    // username or email
    // find the user
    // password check
    //access and refresh token
    // send cookie and response

    const { username,email,password }=req.body
    if(!username || !email){
        throw new ApiError(400,"Username or email is required")
    }
   const user= await User.findOne({
    $or:[{username},{email}]
   })
    if(!user){
        throw new ApiError(404,"User not found")
    }
    const isPasswordValid= await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401,"Invalid user credentials")
    }
       
       const { accessToken, refreshToken } = await generateAccessandRefreshToken(user._id)

       const loggedInUser= await User.findById(user._id).select("-password -refreshToken")

       const options={
        httpOnly:true,
        secure:true,
       }

       return res
       .status(200)
       .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(new Apiresponse(200,loggedInUser,"User logged in successfully"))
} )    

const logoutUser=asyncHandler(async(req,res)=>{
   await User.findByIdAndUpdate(
    req.user._id,
    {
        $set: {
            refreshToken: undefined
        }
    },
    {
        new: true
    }
)
const options={
        httpOnly:true,
        secure:true,
       }
return res.status(200)
.clearCookie("accessToken", options)
.clearCookie("refreshToken", options)
.json(new Apiresponse(200,null,"User logged out successfully"))

      })    

const refreshAccessToken=asynchandler(async(req,res)=>{
  const incomingRefreshToken=req.cookies.refreshToken || req.body.refreshToken

  if(!incomingRefreshToken){
    throw new ApiError(400,"Refresh token is required")

  }
  try {
    const decodedToken=jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
    const user=User.findById(decodedToken?._id)
  
    if(!user){
      throw new ApiError(404,"User not found")
    }
    if(incomingRefreshToken!==user?.refreshToken){
      throw new ApiError(401,"Invalid refresh token")
  
  }  
  const options={
    httpOnly:true,
    secure:true
  }
  const {accessToken,newRefreshToken}=await generateAccessandRefreshToken(user._id)
  
  return 
  res.status(200)
  .cookie("accessToken", accessToken, options)
  .cookie("refreshToken", newRefreshToken, options)
  .json(new Apiresponse(200,
    {accessToken,refreshToken:newRefreshToken},
    "Access token refreshed successfully"))  
  
  }
   catch (error) {
    throw new ApiError(401,error?.message||"Invalid refresh token")
  }
})
export { registerUser, loginUser, logoutUser, refreshAccessToken }  