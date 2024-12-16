import { Router } from "express"
import { createUser, getMyAcount, getProtegido, updateUser, userAutentication } from "./controllers/login-controller"


const router = Router()

router.get("/login/protected", getProtegido)
router.get("/login/myAcount" , getMyAcount)


router.post("/login/create", createUser)
router.post("/login/autentication", userAutentication)

router.patch("/login/:user", updateUser)


export default router