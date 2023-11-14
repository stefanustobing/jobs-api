const { CustomAPIError } = require('../errors')
const { StatusCodes } = require('http-status-codes')
const errorHandlerMiddleware = (err, req, res, next) => {
  //console.log(err);
  let customError={
    //set default
    statusCode:err.statusCode || StatusCodes.INTERNAL_SERVER_ERROR,
    msg: err.message || 'Something went wrong try again later'
  };

  // if (err instanceof CustomAPIError) {
  //   return res.status(err.statusCode).json({ msg: err.message })
  // }
  
  //code error response for duplicate value spit back from mongoose validation
  if (err.code && err.code===11000){
    customError.msg=`Duplicate value entered for ${Object.keys(err.keyValue)} field, please choose another value`;
    customError.statusCode=StatusCodes.BAD_REQUEST
  }

  //code error response for validation error spit back from mongoose validation
  if (err.name==='ValidationError'){
    customError.msg=Object.values(err.errors)
      .map((item)=>item.message)
      .join(',');
    customError.statusCode=StatusCodes.BAD_REQUEST;
  }

  if (err.name==="CastError"){
    customError.msg=`No item found with id: ${err.value}`;
    customError.statusCode=StatusCodes.NOT_FOUND;
  }
  //return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ err })
  return res.status(customError.statusCode).json({ msg:customError.msg })
}

module.exports = errorHandlerMiddleware
