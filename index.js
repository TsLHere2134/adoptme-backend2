import express from "express";

const app = express();
app.use(express.json());

let latestInventory = {};

app.post("/inventory", (req, res) => {
    latestInventory = req.body;
    console.log("Inventory received:", latestInventory.user);
    res.json({ ok: true });
});

app.get("/", (req, res) => {
    res.send(`
        <h1>Backend is running 🔥</h1>
        <pre>${JSON.stringify(latestInventory, null, 2)}</pre>
    `);
});

app.listen(3000, () => {
    console.log("Server running");
});
