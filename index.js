let express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

let application = express();
application.use(cors());
application.use(express.json());

const { DATABASE_URL, SECRET_KEY } = process.env;

//============ SETUP ============
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    require: true,
  },
});

async function getPostgresVersion() {
  const client = await pool.connect();
  try {
    const res = await client.query("select version()");
    console.log(res.rows[0]);
  } finally {
    client.release();
  }
}

getPostgresVersion();

//============ Authentication ============

 application.post('/auth/signup', async(req, res) => {
  const client = await pool.connect();

  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 12);

    const userResult = await client.query('SELECT * FROM users WHERE username = $1', [username]);

    if (userResult.rows.length > 0)
      return res.status(400).json({
        message: "Username has been taken!!"
      });

    await client.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);

    res.status(201).json({
      message: "User has been successfully registered!!"
    });
  } catch (error) {
    console.error("Error from Auth/SignUp: ", error.message);
    res.status(500).json({
      error: error.message
    });
  } finally {
    client.release();
  }
 });

 application.post('/auth/login', async(req, res) => {
  const client = await pool.connect();

  try {
    const result = await client.query('SELECT * FROM users WHERE username = $1', [req.body.username]);

    const user = result.rows[0];

    if (!user){
      return res.status(400).json({
        message: "Username is incorrect or doesn't exist."
      });
    }

    const passwordValid = await bcrypt.compare(req.body.password, user.password);

    if (!passwordValid) {
      return res.status(401).json({
        auth: false,
        token: null
      });
    }
    
    var token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: 86400 });
    res.status(200).json({
      auth: true,
      token: token
    });
  } catch (error) {
    console.error("Error from Auth/Login: ", error.message);
    res.status(500).json({
      error: error.message
    });
  } finally {
    client.release();
  }
 });

//============ POST API ============

application.get('/posts', async(req, res) => {
  const client = await pool.connect();

  try {
    const post = await client.query(`SELECT * FROM posts`);
    res.json(post.rows);
  } catch (err) {
    console.log(err.stack);
    res.status(500).json({
      error: "Something happen that get posts can't execute, please retry again"
    });
  } finally {
    client.release();
  }
});

application.get('/posts/:id', async(req, res) => {
  const id = req.params.id;
  const client = await pool.connect();

  try {
    const post = await client.query(`
        SELECT * FROM posts WHERE user_id = $1
      `, [id]
    );

    res.json(post.rows);
  } catch (err) {
    console.log(err.stack);
    res.status(500).json({
      error: "Something happen that posts/:id can't execute, please retry again"
    });
  } finally {
    client.release();
  }
});

application.post('/posts', async(req, res) => {
  const { author, title, content, thumbnail, userId } = req.body;
  const authToken = req.headers.authorization;
  const token = authToken.split(' ')[1].replace(/"/g, '');
  const client = await pool.connect();

  if (!authToken) 
    return res.status(401).json({ error: 'Access Denied' });

  try {
    const verified = jwt.verify(token, SECRET_KEY);
    if (verified.id !== userId)
      return res.status(400).json({error: "Invalid User"});

    const user = await client.query("SELECT id FROM users WHERE id = $1", [userId]);
    
    if (user.rows.length > 0) {
      const post = await client.query(`
          INSERT INTO posts (author, title, content, thumbnail, user_id, created_at, updated_at)
          VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
          RETURNING *
        `, 
        [author, title, content, thumbnail, userId]
      );

      res.json(post.rows[0]);
    } else {
      res.status(400).json({error: `User with user_id: ${userId} does not exist. Please check the ID.` });
    }
    
  } catch (err) {
    res.status(500).json({
      error: `Something happen that posts can't execute, please retry again: ${err.message}`
    });
  } finally {
    client.release();
  }
});

application.put('/posts/:id', async (req, res) => {
  const client = await pool.connect();
  const id = req.params.id;
  const data = req.body;

  const authToken = req.headers.authorization;
  const token = authToken.split(' ')[1].replace(/"/g, '');

  if (!authToken) 
    return res.status(401).json({ error: 'Access Denied' });

  try {
    const verified = jwt.verify(token, SECRET_KEY);
    if (verified.id !== data.userId)
      return res.status(400).json({error: "Invalid User"});
    
    const result = await client.query(`
        UPDATE posts 
        SET author = $1, title = $2, content = $3, thumbnail = $4, updated_at = CURRENT_TIMESTAMP
        WHERE id = $5
        RETURNING *;
      `, 
      [data.author, data.title, data.content, data.thumbnail, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        status: "error",
        message: "Post not found"
      });
    }

    res.json({
      "status": "success",
      "message": "Post has updated without issues",
      updatedPost: result.rows[0]
    });
  } catch (error) {
    console.error("Error from update posts/id: ", error.message);
    res.status(500).json({
      error: error.message,
      message: id,
    });
  } finally {
    client.release();
  }
});

application.delete('/posts/:id', async (req, res) => {
  const client = await pool.connect();
  const id = req.params.id;
  const { userId } = req.body || {}; ;

  const authToken = req.headers.authorization;
  const token = authToken.split(' ')[1].replace(/"/g, '');

  if (!authToken) 
    return res.status(401).json({ error: 'Access Denied' });

  try {
    const verified = jwt.verify(token, SECRET_KEY);
    if (verified.id !== userId)
      return res.status(400).json({error: `${userId}`});
    
    const selectQuery = 'SELECT * FROM posts WHERE id = $1';
    const result = await client.query(selectQuery, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ "error": "Post not found" });
    }
    const deletedPost = result.rows[0]; 
    
    const deleteQuery = 'DELETE FROM posts WHERE id = $1';
    await client.query(deleteQuery, [id]);

    res.json({ "status": "success", "message": "Post deleted successfully", "deletedPost": deletedPost });
  } catch (error) {
    res.status(500).json({ "error": error.message });
  } finally {
    client.release();
  }
});

//============ Listener ============
application.listen(3000, ( ) => {
  console.log("Server 3000 is active");
});