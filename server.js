const express = require('express');
const mysql = require('mysql2');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const bcrypt = require('bcryptjs');
const LocalStrategy = require('passport-local').Strategy;
const path = require('path');

const app = express();
const port = 3000;


const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'ferreteria'
});


connection.connect(err => {
  if (err) {
    console.error('Error conectando a la base de datos:', err.stack);
    return;
  }
  console.log('Conectado a la base de datos como id ' + connection.threadId);
});

app.use(morgan('combined'));
app.use(bodyParser.urlencoded({ extended: false })); 
app.use(bodyParser.json()); 
app.use(cookieParser());
app.use(session({
  secret: 'mi_secreto',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } 
}));


app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy((username, password, done) => {
  connection.query('SELECT * FROM usuarios WHERE nombreUsuario = ?', [username], async (err, results) => {
    if (err) { return done(err); }
    if (results.length === 0) {
      return done(null, false, { message: 'Usuario no encontrado' });
    }
    const user = results[0];

    try {
      const match = await bcrypt.compare(password, user.clave);

      if (!match) {
        return done(null, false, { message: 'Contraseña incorrecta' });
      }

      return done(null, user);
    } catch (error) {
      return done(error);
    }
  });
}));

passport.serializeUser((user, done) => {
  done(null, user.id_usuario);
});

passport.deserializeUser((id, done) => {
  connection.query('SELECT * FROM usuarios WHERE id_usuario = ?', [id], (err, results) => {
    if (err) { return done(err); }
    done(null, results[0]);
  });
});

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

app.use(express.static(path.join(__dirname, 'paginas')));

app.post('/login', passport.authenticate('local', {
  successRedirect: '/profile.html',
  failureRedirect: '/login.html',
  failureFlash: false
}));

app.post('/register', async (req, res) => {
  const { username, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.status(400).send('Las contraseñas no coinciden');
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10); 
    console.log('Password encriptada:', hashedPassword);

   
    connection.query('INSERT INTO usuarios (nombreUsuario, clave) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
      if (err) {
        console.error('Error al registrar usuario:', err);
        res.status(500).send('Error al registrar usuario');
        return;
      }
      console.log('Usuario registrado con éxito:', results);
      res.redirect('/login.html');
    });
  } catch (error) {
    console.error('Error al encriptar la contraseña:', error);
    res.status(500).send('Error al registrar usuario');
  }
});


app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login.html');
  }
  res.sendFile(path.join(__dirname, 'paginas', 'profile.html'));
});


app.get('/productos', (req, res) => {
  connection.query('SELECT * FROM productos', (err, products) => {
    if (err) {
      console.error('Error al obtener productos:', err);
      res.status(500).send('Error al obtener productos');
      return;
    }
    res.json(products);
  });
});

app.get('/api/user', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ message: 'No autenticado' });
  }
  res.json({ username: req.user.nombreUsuario });
});


app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Error al cerrar sesión:', err);
      return res.status(500).send('Error al cerrar sesión');
    }
    res.redirect('/'); 
  });
});


app.get('/categorias', (req, res) => {
  connection.query('SELECT * FROM categorias', (err, categories) => {
    if (err) {
      console.error('Error al obtener categorías:', err);
      res.status(500).send('Error al obtener categorías');
      return;
    }
    res.json(categories);
  });
});


app.get('/inventario', (req, res) => {
  connection.query('SELECT * FROM inventario', (err, inventory) => {
    if (err) {
      console.error('Error al obtener inventario:', err);
      res.status(500).send('Error al obtener inventario');
      return;
    }
    res.json(inventory);
  });
});

app.post('/agregar-producto', (req, res) => {
  const { nombre, descripcion, precio, stock, categoria_id } = req.body;

  const sql = 'INSERT INTO productos (nombre, descripcion, precio, stock, categoria_id) VALUES (?, ?, ?, ?, ?)';
  const values = [nombre, descripcion, precio, stock, categoria_id];

  connection.query(sql, values, (err, result) => {
    if (err) {
      console.error('Error al agregar producto:', err);
      res.status(500).send('Error al agregar producto');
      return;
    }
    console.log('Producto agregado correctamente');
    res.redirect('/productos.html'); 
  });

  app.delete('/productos/:id', (req, res) => {
    const productId = req.params.id;
  
    const sql = 'DELETE FROM productos WHERE id = ?';
    connection.query(sql, [productId], (err, result) => {
      if (err) {
        console.error('Error al eliminar producto:', err);
        res.status(500).send('Error al eliminar producto');
        return;
      }
      res.json({ message: 'Producto eliminado correctamente' });
    });

    app.put('/productos/:id', (req, res) => {
      const productId = req.params.id;
      const { nombre, descripcion, precio, stock, categoria_id } = req.body;
    
      const sql = 'UPDATE productos SET nombre = ?, descripcion = ?, precio = ?, stock = ?, categoria_id = ? WHERE id = ?';
      const values = [nombre, descripcion, precio, stock, categoria_id, productId];
    
      connection.query(sql, values, (err, result) => {
        if (err) {
          console.error('Error al actualizar producto:', err);
          res.status(500).send('Error al actualizar producto');
          return;
        }
        if (result.affectedRows === 0) {
          res.status(404).send('Producto no encontrado');
          return;
        }
        res.json({ message: 'Producto actualizado correctamente' });
      });
    });

  });
});

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
