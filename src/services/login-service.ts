import { response } from "express"
import { badRequest, conflict, noContent, ok, unauthorized } from "../utils/http-helper"
import { UserModel } from "../models/user-model"
import { autenticateUser, autenticateUserSimple, deleteUsers, findAndModifyUser, insertUser, veryfyEmailDatabase } from "../repositories/login-repository"
import { UserAutenticationModel } from "../models/user-autentication-model"

import jwt from "jsonwebtoken"; /// gerar token
import dotenv from "dotenv";
import { auth } from "../utils/auth"
import { hashedPass } from "../utils/hashedPass"
import { sendEmail } from "../utils/forgotPassSender"







export const getProtegidoService = async (bodyValue: string | undefined) => {

    let response = null
    let data = null   

    data = await auth(bodyValue) /// verificação do token
    
    if (data){
        
        response = await ok(data)
        

    } else{
        

        response = await noContent()

    }
    
    return response

}
export const forgotPassService = async (email: string | undefined) => {

    let response = null
    const secret = process.env.SECRET_KEY

    const verifyEmail = await veryfyEmailDatabase(email)


    
    
    if (verifyEmail && secret) {
        const user = verifyEmail.user
        let token = jwt.sign({ user }, secret, { expiresIn: '1h' });
        token = encodeURIComponent(token)
        const restEmail = `localhost:3000/resetPass/${token}`

        const data = await sendEmail(verifyEmail.email, 'Email teste', restEmail, verifyEmail.user)


        response = await ok(data)
        

    } else{
        

        response = await noContent()

    }
    
    return response

}







export const getMyAcountService = async (bodyValue: string | undefined) => {

    let response = null
    let data = null   

    data = await auth(bodyValue) /// verificação do token
    
    if (data && typeof data !== "string") {
        
        const fullData = await autenticateUserSimple(data.user)
        response = await ok(fullData)
        

    } else{
        

        response = await noContent()

    }
    
    return response

}



export const createUserService = async (bodyValue: UserModel) => {

    
    // criptografando a senha
    bodyValue.passwordHash =  await hashedPass(bodyValue.passwordHash)

    const data = await insertUser(bodyValue)
    let response = null

    if (data) {
        
        response = await ok(data)
    }
    else {
        
        response = await conflict()
    }

    return response

}




export const userAutenticationService = async (bodyValue: UserAutenticationModel) => {

      
    const data = await autenticateUser(bodyValue)
    const secret = process.env.SECRET_KEY
    let response = null
    
    let user = bodyValue.user



    if (data && secret) {
        //gerar o token para futuros gets 
        const token = jwt.sign({ user }, secret, { expiresIn: '1h' });
        response = await ok(token)
    }
    else {
        
        response = await unauthorized()
    }

    return response
}




export const updateUserService = async (user: string, bodyValue: UserModel, authHeader: string | undefined) => {

    const validEmail = bodyValue.email === bodyValue.lastEmail ? true : false;

    const decoded = await auth(authHeader)
    let response = null
      

    if (decoded){
        
        
        const data  = await findAndModifyUser(user, bodyValue, validEmail)
        
        response = await ok(data)
        
        
    } else{
        
        
        response = await badRequest()
        

    }
    
    return response

   
}

export const deleteUserService = async (user: string) => {

    const data = await deleteUsers(user)
    let response = null

    if (data) {
        response = await ok(data)
    }
    else {
        
        response = await badRequest()
    }

    return response


}