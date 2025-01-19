const express = require("express");
const bodyParser = require("body-parser");
const quotes = require("./quotes.json");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.get("/", async function(req, res) {
    res.render("home");
});

app.get("/quote/random", (req, res) => {
    let x = Math.floor((Math.random() * 5420) + 0);
    const random_quote = quotes[x];
    res.json(random_quote);
});

app.get("/quote/:quoteAuthor", (req, res) => {
    const authorName = req.params.quoteAuthor;
    const authorQuotes = quotes.filter((quote) => quote.quoteAuthor === authorName);

    if (authorQuotes.length === 0) {
        return res.status(404).json({
            message: "Quotes not found for the specified author"
        });
    }

    const index = Math.floor(Math.random() * authorQuotes.length);
    const randomQuote = authorQuotes[index];

    res.json(randomQuote);
});

app.use(function(req, res, next) {
    res.status(404).render("404");
});

app.listen(3000, function() {
    console.log("server is running on port 3000");
});