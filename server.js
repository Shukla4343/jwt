const express = require('express');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

dotenv.config();

app.use(express.json());

let users =[
    {id:1,username: 'user1', password: '$2a1$...hashedpassword'}

]
const gnerateToken = (user)=>{
    return jwt.sign(
        {id:user.id, username:user.username},
        process.env.JWT_SECRET_KEY,
        {expiresIn: process.env.JWT_EXPIRE_TIME}
    );
};
app.post('/signup', async(req,res)=>{
    const { username, passowrd} = req.body;
    const existingUser = user.find(u => u.username === username);
    if(existingUser){
        return res.status(400).json({message: 'username already taken'});

    }
    const hashedPassword = await bcrypt.hash(passowrd,10);
    const newUser = {id: Date.now(), username, passowrd: hashedPassword};
    user.push(newUser);
    const token = gnerateToken(newUser);
    return res.status(201).json({token});
});
 
//LOGIN ROUTE START HERE
app.post('/login',async(req,res)=>{
    const {username,passowrd} = req.body;
    const user = user.find(u => u.userrname === username);
    if(!user){
        return res.status(401).json({message: 'Invalid username or passowrd'});
    }
    const isPasswordValid = await bcrypt.compare(passowrd, user.passowrd);
    if(!isPasswordValid){
        return res.status(401).json({message: 'Invalid username or passowrd'});
    }
    const token = generateToken(user);
    return res.json({token});
});
const verifyToken = (req,res,next)=>{
    const token = req.header('Authorization')?.replace('Bearer','');
    if(!token){
        return res.status(401).json({message: 'No token provided'});
    }
    try{
        const decode = jwt.verify(token, process.env.JWT_SECRET_KEY);
        req.user = decoded;
        next();

    }catch(err){
        return res.status(401).json({message: 'Invalid or expired token'});
    }
};

app.get('/protected', verifyToken, (req,res)=>{
    res.json({message: 'Welcome to the protected route', user: req.user});
})

const PORT = process.env.PORT || 5000;
app.listen(PORT,()=>{
    console.log(`server running on port ${PORT}`);
});