import { UserModel } from "../models/user-model";
import { MongoClient } from "mongodb";
import dotenv from "dotenv";
import { UserAutenticationModel } from "../models/user-autentication-model";

// Carregar variáveis de ambiente
dotenv.config();

// Configuração da conexão MongoDB
const uri: string = process.env.MONGO_URI;
const client = new MongoClient(uri);
let cachedDb: any = null;

// Conectar ao banco de dados (reutilizando a conexão se já estiver aberta)
const connectDatabase = async () => {
  if (cachedDb) {
    return cachedDb;
  }

  await client.connect();
  const database = client.db(process.env.DATABASE);
  cachedDb = database.collection(process.env.COLLECTION);
  return cachedDb;
};

// Fechar a conexão com o banco de dados
const closeDatabase = async () => {
  if (client) {
    await client.close();
  }
};

// -------------------------------------------------------- GET / READ


export const autenticateUser = async (value: UserAutenticationModel): Promise<UserModel | undefined> => { 

  const collection = await connectDatabase();
  const filter = { user: value.user };
  const result = await collection.findOne(filter);


  if (result && value.passwordHash === result.passwordHash) {
    
    return result;

  } 

  return 

}

export const autenticateUserSimple = async (value: String): Promise<UserModel | undefined> => { 

  const collection = await connectDatabase();
  const filter = { user: value };
  const result = await collection.findOne(filter);


  if (result) {
    
    return result;

  } 

  return 

}






// -------------------------------------------------------- INSERT (Create)

export const insertUser = async (value: UserModel) => {
    
//resolver problemas de usuários repedidos

  const collection = await connectDatabase();  
  
  const filter = { user: value.user };
  const result = await collection.findOne(filter);

  if (!result) {
    
    await collection.insertOne(value);
    return { message: "created" };

  } else {
    
    return
  }
    

};




// -------------------------------------------------------- DELETE



// -------------------------------------------------------- UPDATE


export const findAndModifyUser = async (user: string, body: UserModel) => {
  const collection = await connectDatabase();
  
  try {
    const filter = { user: user };
    const updatedUser = { ...body, user: user };
    const result = await collection.replaceOne(filter, updatedUser);

    if (result.matchedCount === 1) {
      return { message: "updated" };
    } else {
      return { message: "not found" };
    }
  } catch (error) {
    console.error("Error updating food:", error);
    return { message: "error", error: error.message };
  }
};