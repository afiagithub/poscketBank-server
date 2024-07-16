const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const express = require('express')
const app = express()
const cors = require('cors')
const jwt = require('jsonwebtoken');
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

    app.get("/user", async (req, res) => {
        const email = req.query.email;
        const pin = req.query.pin;
        const query = { email: email, pin: pin};
        const result = await userCollection.findOne(query);
        res.send(result)
    })

    app.post("/users", async (req, res) => {
        const user = req.body;
        const result = await userCollection.insertOne(user);
        res.send(result)
    })


    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
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