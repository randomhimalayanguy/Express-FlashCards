import express, {Request, Response, NextFunction} from 'express';
import mongoose, {Schema, Types} from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import {body, validationResult} from 'express-validator';
require('dotenv').config();

const app = express();
const port = process.env.PORT;
const mongoDBURI = process.env.MONGODB_URI;
const SECRET_KEY = process.env.JWT_SECRET_KEY;

mongoose.connect(mongoDBURI as string)
.then(()=>console.log(`Connected to db`))
.catch((err)=>console.log(`Can't connect to db : ${err}`));


class AppError extends Error{
    statusCode : number;
    constructor(err : string, statusCode = 500){
        super(err);
        this.statusCode = statusCode;
    }
}



// interfaces
interface AuthRequest extends Request{
    user? : {userId : string}
}


interface IUser extends mongoose.Document{
    username : string,
    password : string,
    decks : mongoose.Types.ObjectId[]
}


interface ICard{
    frontText : string,
    backText : string,
    nextReview : Date,
    ease : number,
    interval : number
}


interface IDeck extends mongoose.Document{
    name : string,
    desc : string,
    ownerId : mongoose.Types.ObjectId,
    cards : ICard[]
}


// schemas
const userSchema = new Schema<IUser>({
    username : {type : String, required : true, unique : true},
    password : {type : String, required : true},
    decks : [{type : Schema.Types.ObjectId, unique : true, ref : 'Decks'}]
});


const cardSchema = new Schema<ICard>({
    frontText : {type : String, required : true},
    backText : {type : String, required : true},
    nextReview : {type : Date, required : true, default : ()=> new Date(Date.now())},
    ease : {type : Number, required : true, min : 1, max : 5, default : 2.5},
    interval : {type : Number, required : true, min : 0, default : 0}
});


const deckSchema = new Schema<IDeck>({
    name : {type : String, required : true, minlength : 3, trim : true},
    desc : {type : String, required : true, minlength : 5, trim : true},
    ownerId : {type : Schema.Types.ObjectId, required : true, ref : 'User'},
    cards : [cardSchema]
});


// schema pre ->
userSchema.pre('save', async function(next){
    if(!this.isModified('password')) return next();

    this.password = await bcrypt.hash(this.password, 12);
    next();
});


// models
const User = mongoose.model('User', userSchema);

const Decks = mongoose.model('Decks', deckSchema);



// middlewares
app.use(express.json());
app.use(cors());



const authenticate = (req : AuthRequest, res : Response, next : NextFunction)=>{
    try{
        const authHeader = req.header('Authorization');
        if(!authHeader || !authHeader.startsWith('Bearer '))
            return next(new AppError(`No tokken provided`, 400));

        const token = authHeader.split(' ')[1];

        const decoded = jwt.verify(token, SECRET_KEY as string) as {userId : string};
        req.user = decoded;

        next();
    }
    catch(err){
        next(new AppError(`Can't authenticate : ${err}`, 401));
    }
};


const validateCards = [
    body('cards').isArray({min : 1}).withMessage("Card must be non empty array"),
    body('cards.*.frontText').isString().trim().escape().isLength({min : 1}).withMessage("Front text must not be empty"),
    body('cards.*.backText').isString().trim().escape().isLength({min : 1}).withMessage('Back text must not be empty'),

    // Checks error
    (req : Request, res : Response, next : NextFunction)=>{
        try{
            const errors = validationResult(req);
            if(!errors.isEmpty())
                return next(new AppError(`Validation Error : ${errors.array().map(e => e.msg).join(', ')}`, 400));

            next();
        }
        catch(err){
            next(new AppError(`Can't validate : ${err}`, 500));
        } 
    }
];

// routes
app.post('/register', async (req : Request, res : Response, next : NextFunction)=>{
    try{
        const {username, password} = req.body;
        if(!username || !password)
            return next(new AppError(`You must provide username and password`, 400));

        if(password.length < 6)
            return next(new AppError(`Password length must be atleast 6 characters long`, 400));

        const existingUser = await User.findOne({username});
        if(existingUser)
            return next(new AppError(`User already exist`, 409));

        const user = new User({
            username : username,
            password : password,
            decks : []
        });

        await user.save();

        const {password : _, ...userWithoutPassword} = user.toObject();
        res.status(201).json({Msg : "User registered", User : userWithoutPassword});
    }
    catch(err){
        next(new AppError(`Can't register : ${err}`, 500));
    }
});


app.post('/login', async (req : Request, res : Response, next : NextFunction)=>{
    try{
        const {username, password} = req.body;
        if(!username || !password)
            return next(new AppError(`You must provide username and password`, 400));

        const user = await User.findOne({username});

        if(!user)
            return next(new AppError(`User doesn't exist, register first`, 409));

        if(!(await bcrypt.compare(password, user.password)))
            return next(new AppError(`Invalid credentials`, 401));

        const token = jwt.sign({userId : user._id}, SECRET_KEY as string, {expiresIn : '3h'});
        const {password : _, ...userWithoutPassword} = user.toObject();

        res.status(201).json({Msg : "User logged in", User : userWithoutPassword, Token : token});
    }
    catch(err){
        next(new AppError(`Can't login : ${err}`, 500));
    }
});



app.get('/decks', authenticate, async (req : AuthRequest, res : Response, next : NextFunction)=>{
    try{
        const user = await User.findById(req.user?.userId).populate('decks');
        if(!user)
            return next(new AppError(`User doesn't exist`, 404));

        const decks = user.decks;
        res.status(200).json({Msg : "Decks retrieved", Decks : decks});
    }
    catch(err){
        next(new AppError(`Can't load decks : ${err}`, 500));
    }
});


app.post('/decks', authenticate, async (req : AuthRequest, res : Response, next : NextFunction)=>{
    try{
        const {name, desc} = req.body;

        const user = await User.findById(req.user?.userId);
        if(!user)
            return next(new AppError(`User doesn't exist`, 404));

        const deck = new Decks({
            name : name, 
            desc : desc,
            ownerId : user._id,
            cards : []
        });

        await deck.save();
        user.decks.push(deck.id as Types.ObjectId);
        await user.save();
        res.status(201).json({Msg : "Deck created", Deck : deck});
    }
    catch(err){
        next(new AppError(`Can't post deck : ${err}`, 500));
    }
});


app.post('/decks/:deckId/cards', authenticate, validateCards, 
    async (req : AuthRequest, res : Response, next : NextFunction)=>{
    try{
        const {cards} = req.body;

        const deckId = req.params.deckId;
        const deck = await Decks.findOne({_id : deckId});
        if(!deck)
            return next(new AppError(`No deck with this id`, 404));

        deck.cards.push(...cards);
        await deck.save();

        res.status(201).json({Msg : "Cards added", Deck : deck});
    }
    catch(err){
        next(new AppError(`Can't add cards : ${err}`, 500));
    }
});


app.get('/decks/:deckId/review', authenticate, async (req : AuthRequest, res : Response, next : NextFunction)=>{
    try{
        const deckId = req.params.deckId;
        const deck = await Decks.findOne({_id : deckId});
        if(!deck)
            return next(new AppError(`No deck exist with this id`, 404));

        const user = await User.findById(req.user?.userId);
        if(!user)
            return next(new AppError(`User does not exist`, 404));

        if(user.id !== String(deck.ownerId))
            return next(new AppError(`You don't have access to this deck`, 403));

        const now = new Date();
        const pipeline = [
            { $match : { _id : deck._id } },
            { $unwind : '$cards' },
            { $match : { 'cards.nextReview': { $lte:  now} } },
            { 
               $project: {
                    deckId: '$_id',
                    deckName: '$name',
                    cardId: '$cards._id',
                    frontText: '$cards.frontText',
                    backText: '$cards.backText',
                    nextReview: '$cards.nextReview',
                    ease: '$cards.ease',
                    interval: '$cards.interval',
                }
            },
            { $limit : 20 }
        ];
        const cards = await Decks.aggregate(pipeline).exec();
        res.status(200).json({Msg : 'Review cards retrieved', Cards : cards});
    }
    catch(err){
        next(new AppError(`Can't access the deck : ${err}`, 500));
    }
});

app.patch('/decks/:deckId/cards/:cardId/review', authenticate, 
    [body('ease').isInt({min : 1, max : 5}).withMessage('Ease should be an interger between 1 and 5')],
    async (req : AuthRequest, res : Response, next : NextFunction)=>{
    try{
        const errors = validationResult(req);
        if(!errors.isEmpty())
            return next(new AppError(errors.array().map(e => e.msg).join(', '),400));

        const { ease }  = req.body;
        
        const deckId = req.params.deckId;
        const cardsId = req.params.cardId;

        const deck = await Decks.findOne({_id : deckId});

        if(!deck)
            return next(new AppError(`No deck with this id`, 404));

        const user = await User.findById(req.user?.userId);
        if(!user)
            return next(new AppError(`User does not exist`, 404));

        if(user.id !== String(deck.ownerId))
            return next(new AppError(`You don't have access to this deck`, 409));

        const cardsDeck = await Decks.findOne({_id : deckId, 'cards._id' : cardsId}).select('cards.$');
        if(!cardsDeck)
            return next(new AppError(`No card with this id`, 404));

        const card = cardsDeck.cards[0];
        const now = new Date();
        card.ease = ease;

        if(ease >= 3)
            card.interval = card.interval * 2 + 1;
        else
            card.interval = 1;

        now.setDate(now.getDate() + card.interval);
        card.nextReview = now;

        await deck.save();
        res.status(200).json({Msg : 'Card review updated', Card : card});
    }
    catch(err){
        next(new AppError(`Can't edit the ease : ${err}`));
    }
});


app.delete('/decks/:deckId', authenticate, async (req : AuthRequest, res : Response, next : NextFunction)=>{
    try{
        const user = await User.findById(req.user?.userId);
        if(!user)
            return next(new AppError(`User doesn't exist`, 404));

        const deckId = req.params.deckId;
        const deck = await Decks.findById(deckId);
        if(!deck)
            return next(new AppError(`No deck with this id`, 404));

        if(!deck.ownerId.equals(String(user._id)))
            return next(new AppError(`You don't have access to delete this`, 409));

        await Decks.findOneAndDelete({_id : deckId});
        user.decks = user.decks.filter(id => String(id) !== String(deckId));     
        await user.save();
        
        res.status(200).json({Msg : "Deck deleted"});
    }
    catch(err){
        next(new AppError(`Can't delete : ${err}`));
    }
});


app.use((err : AppError, req : Request, res : Response, next : NextFunction)=>{
    console.log(`${err.statusCode} : ${err.message}`);
    res.status(err.statusCode).json({Error : err.message});
});


app.listen(port, ()=>console.log(`Server started on : http://localhost:${port}`));
