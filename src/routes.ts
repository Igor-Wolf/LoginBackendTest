import { Router } from "express"
import { createUser, getProtegido, updateUser, userAutentication } from "./controllers/login-controller"


const router = Router()

router.get("/login/protected" , getProtegido)


router.post("/login/create", createUser)
router.post("/login/autentication", userAutentication)

router.patch("/login/:user", updateUser)


export default router