const express = require("express");
const app = express();
app.use(express.json());
const cors = require("cors");
app.use(cors());
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const dns = require("node:dns/promises");
dns.setServers(["1.1.1.1", "8.8.8.8"]);
const { MongoClient, ObjectId } = require("mongodb");
require("dotenv").config();

const client = new MongoClient(process.env.MONGO_URI);

let db;
let usersCollection;
let transactionsCollection;

async function connectDB() {
  try {
    await client.connect();
    db = client.db("moneyDemo");
    usersCollection = db.collection("users");
    transactionsCollection = db.collection("transactions");
    console.log("MongoDB connected!");
    return true;
  } catch (err) {
    console.error("Failed to connect to MongoDB:", err.message || err);
    return false;
  }
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send("No token");

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).send("Invalid token");
    req.user = decoded;
    next();
  });
}

app.post("/register", async (req, res) => {
  console.log("POST /register hit! Body:", req.body);
  const { name, email, password } = req.body;
  const existing = await usersCollection.findOne({ email });
  if (existing) return res.status(400).send("User already exists");

  const hashed = await bcrypt.hash(password, 10);

  await usersCollection.insertOne({
    name,
    email,
    password: hashed,
    createdAt: new Date(),
  });

  res.send("User registered successfully");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await usersCollection.findOne({ email });
  if (!user) return res.status(400).send("User not found");

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).send("Wrong password");

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.json({ token });
});

app.post("/transactions", verifyToken, async (req, res) => {
  const data = req.body;
  await transactionsCollection.insertOne({
    ...data,
    userId: new ObjectId(req.user.id),
    createdAt: new Date(),
  });
  res.send("Transaction added");
});

app.get("/transactions", verifyToken, async (req, res) => {
  const transactions = await transactionsCollection
    .find({ userId: new ObjectId(req.user.id) })
    .toArray();
  res.json(transactions);
});

app.put("/transactions/:id", verifyToken, async (req, res) => {
  await transactionsCollection.updateOne(
    { _id: new ObjectId(req.params.id), userId: new ObjectId(req.user.id) },
    { $set: req.body },
  );
  res.send("Transaction updated");
});

app.delete("/transactions/:id", verifyToken, async (req, res) => {
  await transactionsCollection.deleteOne({
    _id: new ObjectId(req.params.id),
    userId: new ObjectId(req.user.id),
  });
  res.send("Transaction deleted");
});

app.get("/stats/monthly", verifyToken, async (req, res) => {
  const userId = new ObjectId(req.user.id);
  const transactions = await transactionsCollection.find({ userId }).toArray();

  const income = transactions
    .filter((t) => t.type === "income")
    .reduce((a, b) => a + b.amount, 0);
  const expense = transactions
    .filter((t) => t.type === "expense")
    .reduce((a, b) => a + b.amount, 0);

  res.json({
    totalIncome: income,
    totalExpense: expense,
    balance: income - expense,
  });
});

const PORT = process.env.PORT || 5001;
app.get("/", (req, res) => res.send("Demo API running"));
app.get("/demo/transactions", (req, res) => {
  res.json([
    { id: 1, title: "Salary", amount: 50000, type: "income" },
    { id: 2, title: "Groceries", amount: 2000, type: "expense" },
    { id: 3, title: "Freelance", amount: 15000, type: "income" },
  ]);
});
app.get("/demo/transactions/:id", (req, res) => {
  res.json({
    id: req.params.id,
    title: "Sample Transaction",
    amount: 3000,
    type: "expense",
    createdAt: new Date(),
  });
});
app.get("/demo/stats/monthly", (req, res) => {
  res.json({
    totalIncome: 65000,
    totalExpense: 20000,
    balance: 45000,
  });
});

(async () => {
  const ok = await connectDB();
  if (!ok) {
    console.error(
      "Exiting: unable to connect to MongoDB. Check MONGO_URI and network settings.",
    );
    process.exit(1);
  }

  app.listen(PORT, () => console.log("Server running on " + PORT));
})();
