const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const express = require('express')
const app = express()
const cors = require('cors')
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config()
const port = process.env.PORT || 5000;

// middleware
app.use(cors({
    origin: ["http://localhost:5173", "https://pocketbank-auth.web.app", "https://pocketbank-auth.firebaseapp.com"],
    credentials: true
}))
app.use(express.json())

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ctn12zm.mongodb.net/?appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();
        const userCollection = client.db('bankDB').collection('users');
        const tranCollection = client.db('bankDB').collection('transactions');

        app.post("/jwt", async (req, res) => {
            const user = req.body;
            // console.log(user);
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' })
            res.send({ token })
        })

        const verifyToken = async (req, res, next) => {
            const auth = req.headers.authorization;
            if (!auth) {
                return res.status(401).send({ message: 'not authorized' })
            }

            const token = req.headers.authorization.split(' ')[1];
            jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded) => {
                if (error) {
                    return res.status(401).send({ message: 'not authorized' })
                }
                // console.log('value token: ', decoded);
                req.decoded = decoded;
                next();
            })
        };

        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            // console.log(email);
            const query = { email: email };
            const user = await userCollection.findOne(query);
            const isAdmin = user?.role === 'admin';
            if (!isAdmin) {
                return res.status(403).send({ message: "forbidden access" })
            }
            next();
        }

        const verifyAgent = async (req, res, next) => {
            const email = req.decoded.email;
            // console.log(email);
            const query = { email: email };
            const user = await userCollection.findOne(query);
            const isAgent = user?.role === 'agent';
            if (!isAgent) {
                return res.status(403).send({ message: "forbidden access" })
            }
            next();
        }

        app.get("/users/admin/:email", verifyToken, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: "forbidden access" })
            }
            const query = { email: email };
            const user = await userCollection.findOne(query);
            // console.log(user);
            let admin = false;
            if (user) {
                admin = user?.role === 'admin'
                // console.log(admin);
            }
            res.send({ admin })
        })

        app.get("/users/agent/:email", verifyToken, async (req, res) => {
            const email = req.params.email;
            if (email !== req.decoded.email) {
                return res.status(403).send({ message: "forbidden access" })
            }
            const query = { email: email };
            const user = await userCollection.findOne(query);
            let agent = false;
            if (user) {
                agent = user?.role === 'agent'
            }
            res.send({ agent })
        })

        app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
            const result = await userCollection.find().toArray();
            res.send(result)
        })

        app.post("/users", async (req, res) => {
            const { name, email, pin, mobile, role, balance, status } = req.body;
            const encryptedPin = await bcrypt.hash(pin, 10);
            const newUser = {
                name,
                email,
                pin: encryptedPin,
                mobile,
                role,
                balance,
                status
            };
            const result = await userCollection.insertOne(newUser);
            res.send(result)
        })

        app.get("/users/:email", verifyToken, async (req, res) => {
            const email = req.params.email;
            const query = { email: email };
            const result = await userCollection.findOne(query);
            res.send(result)
        })

        app.patch("/active-first/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const money = parseInt(req.query.money);
            const bal = parseInt(req.query.balance);
            const newBal = bal + money;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    balance: newBal,
                    openBonus: 'given',
                    status: 'active'
                }
            }
            const result = await userCollection.updateOne(filter, updatedDoc);
            res.send(result)
        })

        app.patch("/active-user/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    status: 'active'
                }
            }
            const result = await userCollection.updateOne(filter, updatedDoc);
            res.send(result)
        })

        app.patch("/block-user/:id", verifyToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    status: 'blocked'
                }
            }
            const result = await userCollection.updateOne(filter, updatedDoc);
            res.send(result)
        })

        app.get("/search-name", async (req, res) => {
            const name = req.query.name;
            const query = { name: name }
            const result = await userCollection.find(query).toArray()
            res.send(result)

        })

        app.post("/pin-check", async(req, res) => {
            const {email, pin} = req.body;
            const user = await userCollection.findOne({email: email});
            if(!user){
                return res.json({ error: "User Not Found" })
            }
            if (await bcrypt.compare(pin, user.pin)){
                return res.json({status: 'ok'})
            }
            return res.json({ status: "Wrong PIN" })
        })

        app.post("/transac", async (req, res) => {
            const data = req.body;
            const { mobile, rcvr_mobile, amount } = req.body;
            const query = {
                mobile: rcvr_mobile,
                role: 'user'
            }
            const rcvr = await userCollection.findOne(query);
            if (!rcvr) {
                res.send({ message: 'No Receiver Found' })
                return
            }
            const sender = await userCollection.findOne({mobile: mobile});
            const updateSender = await userCollection.updateOne(
                { mobile: mobile },
                {
                    $inc:
                    {
                        balance: -amount
                    }
                }
            );
            let rcvr_amount = amount;
            if(amount > 100){
                rcvr_amount = amount-5
            }
            const updateRcvr = await userCollection.updateOne(
                { mobile: rcvr_mobile },
                {
                    $inc:
                    {
                        balance: rcvr_amount
                    }
                }
            );
            if (!updateSender || !updateRcvr) {
                res.send({ message: 'Something went wrong' })
                return
            }
            const result = await tranCollection.insertOne(data)
            res.send(result)
        })

        app.get("/transac/:email", verifyToken, async(req, res) =>{
            const email = req.params.email;
            const result = await tranCollection.find({email: email}).limit(10).toArray();
            res.send(result)
        })

        app.get("/alltransac", verifyToken, async(req, res) =>{
            const result = await tranCollection.find().toArray();
            res.send(result)
        })

        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('PocketBank Server Running')
})

app.listen(port, () => {
    console.log(`PocketBank Server Running on port ${port}`)
})