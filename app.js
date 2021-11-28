const express = require('express')
const bcrypt = require('bcryptjs')
const session = require('express-session')
const MongoDBSession = require('connect-mongodb-session')(session)
const mongoose = require('mongoose')
const UserModel = require('./models/User')
const app = express()


app.set('view engine','ejs')
app.set('views','views')
app.use(express.urlencoded({extended:true}))

const DB_URL = 'mongodb://localhost:27017/sessions'
mongoose.connect(DB_URL)

const store = new MongoDBSession({
    uri:DB_URL,
    collection:'mySessions',
})

app.use(session({
    secret:'key that will sign cookie',
    resave:false,
    saveUninitialized:false,
    store:store,
}))

const isAuth = (req,res,next)=>{
    if(req.session.isAuth){
        next()
    }else{
        res.redirect('/login')
    }
}

app.get('/',(req,res,next)=>{
   res.render('landing')
})

app.get('/login',(req,res,next)=>{
    res.render('login')
})

app.post('/login',async(req,res,next)=>{
    const {email,password} = req.body
    let user = await UserModel.findOne({email})
    if(!user){
        return res.redirect('/login')
    }

    const isMatch = await bcrypt.compare(password,user.password)
    
    if(!isMatch){
        console.log(isMatch);
        return res.redirect('/login')
    }
    req.session.isAuth = true   
    res.redirect('/dashbord')
})

app.get('/register',(req,res,next)=>{
    res.render('register')
})


app.post('/register',async(req,res,next)=>{
    const {username,email,password} = req.body
    let user = await UserModel.findOne({email})
    if(user){
        return res.redirect('/register')
    }

    const hashPsw = await bcrypt.hash(password,12)

    user = new UserModel({
        username,
        email,
        password:hashPsw
    })

    await user.save()
    res.redirect('/login')
})

app.get('/dashbord',isAuth,(req,res,next)=>{
    res.render('dashbord')
})

app.post('/logout',(req,res,next)=>{
    req.session.destroy((err)=>{
        if(err) throw err
        res.redirect('/')
    })
})


app.listen(3000,()=>{
    console.log('server runing in port 3000');
})