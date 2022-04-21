game-tester@game-server:/usr/src/app$ cat server.js 
'use strict';

var express = require('express');
var ip = require('ip');

const PORT = 9999;
var rounds = 3;

// App
var app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

/**
 * https://stackoverflow.com/a/1527820
 * 
 * Returns a random integer between min (inclusive) and max (inclusive).
 * The value is no lower than min (or the next integer greater than min
 * if min isn't an integer) and no greater than max (or the next integer
 * lower than max if max isn't an integer).
 * Using Math.round() will give you a non-uniform distribution!
 */
function random(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * https://stackoverflow.com/a/11377331
 * 
 * Returns result of game (randomly determined)
 * 
 */
function play(player = -1)
{
  // Random numbers to determine win
  if (player == -1)
    player = random(1, 3);
  var computer = random(1, 3);
  
  if (player == computer) return 'tie';
  else if ((player - computer + 3) % 3 == 1) return 'win';
  else return 'loss';
}

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/autoplay', (req,res) => {
  res.render('autoplay');
});

app.get('/rock', (req,res) => {
  res.render('index', {result:play(1)});
});

app.get('/paper', (req,res) => {
  res.render('index', {result:play(2)});
});

app.get('/scissors', (req,res) => {
  res.render('index', {result:play(3)});
});

app.post('/autoplay', async function autoplay(req,res) {
  
  // Stop execution if not number
  if (isNaN(req.body.rounds))
  {
    res.sendStatus(500);
    return;
  }
  // Stop execution if too many rounds are specified (performance issues may occur otherwise)
  if (req.body.rounds > 100)
  {
    res.sendStatus(500);
    return;
  }

  rounds = req.body.rounds;

  res.write('<html><body>')
  res.write('<h1>Starting autoplay with ' + rounds + ' rounds</h1>');
  
  var counter = 0;
  var rounds_ = rounds;
  var wins = 0;
  var losses = 0;
  var ties = 0;

  while(rounds != 0)
  {
    counter++;
    var result = play();
    if(req.body.verbose)
    {
      res.write('<p><h3>Playing round: ' + counter + '</h3>\n');
      res.write('Outcome of round: ' + result + '</p>\n');
    }
    if (result == "win")
      wins++;
    else if(result == "loss")
      losses++;
    else
      ties++;
      
    // Decrease round
    rounds = rounds - 1;
  }
  rounds = rounds_;

  res.write('<h4>Stats:</h4>')
  res.write('<p>Wins: ' + wins + '</p>')
  res.write('<p>Losses: ' + losses + '</p>')
  res.write('<p>Ties: ' + ties + '</p>')
  res.write('<a href="/autoplay">Go back</a></body></html>')
  res.end()
});

app.listen(PORT, "0.0.0.0");
console.log(`Running on http://${ip.address()}:${PORT}`);