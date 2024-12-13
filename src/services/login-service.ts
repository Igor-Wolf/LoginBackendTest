import { response } from "express"
import { badRequest, conflict, noContent, ok, unauthorized } from "../utils/http-helper"
import { UserModel } from "../models/user-model"
import { autenticateUser, findAndModifyUser, insertUser } from "../repositories/login-repository"
import { UserAutenticationModel } from "../models/user-autentication-model"

import jwt from "jsonwebtoken"; /// gerar token
import dotenv from "dotenv";
import { auth } from "../utils/auth"







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



export const createUserService = async (bodyValue: UserModel) => {

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

    const decoded = await auth(authHeader)
    let response = null
    

    if (decoded){
        
        const data  = await findAndModifyUser(user, bodyValue)
        
        response = await ok(data)
        
        
    } else{
        
        
        response = await badRequest()
        

    }
    
    return response










    

    

}