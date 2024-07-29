export default () => ({
  jwt: {
    secret: `${process.env.JWT_SECRET_KEY}`,
  },
  database: {
    connnectionString: `${process.env.MONGO_URL}`,
  },
});
