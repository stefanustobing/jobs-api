const User=require('../models/User');
const jwt=require('jsonwebtoken');
const {UnauthenticatedError}=require('../errors');

const authenticationMiddleware= async (req,res,next)=>{
    const authHeader=req.headers.authorization;
    //To check if the request header contains authorization: Bearer fdsfiIOJO3453....
    if (!authHeader || !authHeader.startsWith('Bearer ')){
        throw new UnauthenticatedError ('Authentication invalid')
    }

    const token=authHeader.split(' ')[1];
    //console.log(token)
    try {
        //verify the token sent from the front-end
        const payload= await jwt.verify(token,process.env.JWT_SECRET);
        //destructure the payload information when the token is verified
        const {userId,name}=payload;
        //inject the user information got from payload and inject it to req.user
        req.user={userId,name}
        next()
    } catch (error) {
        throw new UnauthenticatedError ('Authentication invalid')
    }
}

module.exports=authenticationMiddleware;