import 'dotenv/config';
import express, { NextFunction, Response, Request } from 'express';
import { z } from 'zod';
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors'



const app = express()
app.use(helmet());
app.use(cors({
    origin: 'http://127.0.0.1:3000',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}))

app.use(express.json())




const authLimiter = rateLimit({
    windowMs: 15*60*1000,
    max: 5,
    message: {
        error: "Muitas tentativas a partir desse IP. Tente novamente após 15 minutos"
    },
    standardHeaders: true,
    legacyHeaders: false,
});


const JWT_SECRET = process.env.JWT_SECRET || "chave_fallback_desenvolvimento"
const PORT = process.env.PORT || 3000

interface AuthenticatedRequest extends Request{
    user?: {userId: string; email: string;}
};

const usersDB: {id: string; email: string, passwordHash: string}[] = []

const authSchema = z.object({
    email: z.string().email({message: "E-mail com formato inválido"}),
    password: z.string().min(8, {message: "A senha precisa ter no mínimo 8 caracteres"})
});


function authMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction){
    const authHeader = req.get('authorization');


    if (!authHeader){
        return res.status(401).json({error: "Token de autenticação não fornecido"}

        )}

    const parts = authHeader.split(" ")
    if(parts.length !==2 || parts[0] !== "Bearer"){
        return res.status(401).json({error: "Formato de token inválido. Use: Bearer <token>"})
    }

    const token = parts[1]

    if (!token){
        return res.status(401).json({error: "Token não fornecido"});
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as {userId: string; email: string}
        req.user = decoded

        return next()
    } catch (err){
        return res.status(401).json({error: "Token inválido ou expirado"})
    }


    
}

app.post('/register',authLimiter, async (req, res) =>{
    const result = authSchema.safeParse(req.body);


    if (!result.success){
        return res.status(400).json({
            error: "Entrada inválida",
            detalhes: result.error.format()
        })
    }

const {email, password} = result.data


const usersExist = usersDB.find(u=> u.email === email);

if (usersExist){
    return res.status(400).json({error: "E-mail já cadastrado"})
}

const passwordHash = await bcrypt.hash(password, 10);


const newUser = {id: String(usersDB.length + 1), email, passwordHash}
usersDB.push(newUser)

return res.status(201).json({
    message: "Usuário cadastrado com sucesso",
    user: {id: newUser.id, email: newUser.email}
})
});


app.post('/login', authLimiter, async (req, res)=>{
    const result = authSchema.safeParse(req.body);
    if(!result.success) {
        return res.status(400).json({error: "Entrada inválida", detalhes: result.error.format()})
    }


    const {email, password} = result.data

    const user = usersDB.find(u => u.email === email);

    if(!user){
        return res.status(401).json({error: "Credenciais inválidas."})
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash)
    if (!isPasswordValid){
        return res.status(401).json({error: "Credenciais inválidas"})
    }


    const token = jwt.sign(
        {userId: user.id, email: user.email},
        JWT_SECRET,
        {expiresIn: '1h'}
    )

    return res.json({
        message: "Login realizado co sucesso!",
        token
    })
})

app.get('/profile', authMiddleware, (req: AuthenticatedRequest, res: Response) =>{
    return res.json({
        message: "Acesso autorizado ao perfil privado!",
        usuarioLogado: req.user
    })
})

app.listen(PORT, ()=> console.log(`Servidor rodando com autenticação e hash na porta ${PORT}!`))


