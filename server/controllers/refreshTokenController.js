const User = require("../model/User");
const jwt = require("jsonwebtoken");

const handleRefreshToken = async (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(401);
  const refreshToken = cookies.jwt;
  // Clear cookie after receiving RefreshToken
  res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });

  // Search the user that has refreshToken
  const foundUser = await User.findOne({ refreshToken }).exec();

  // Detected refreshToken reuse.
  // In case if user with this refreshToken not found,
  // that means the refresh token has already been invalidated (in our setup it means token was removed from refreshToken array)
  if (!foundUser) {
    // Decode username from refresh token and try to find this user in DB to delete all refresh tokens from refreshToken array
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      async (err, decoded) => {
        // if we can't decode the refresh token that means it's expired and we just return 403
        if (err) return res.sendStatus(403); //Forbidden

        //otherwise if it's a valid, we know someone is attempting to use a refresh token. It's refreshToken reuse case
        // we find user and delete all refresh tokens from refreshToken array
        const hackedUser = await User.findOne({
          username: decoded.username,
        }).exac();
        hackedUser.refreshToken = [];
        const result = await hackedUser.save();
        console.log({ result });
      }
    );

    return res.sendStatus(403); //Forbidden
  }

  // evaluate jwt
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err || foundUser.username !== decoded.username)
      return res.sendStatus(403);
    const roles = Object.values(foundUser.roles);
    const accessToken = jwt.sign(
      {
        UserInfo: {
          username: decoded.username,
          roles: roles,
        },
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "30s" }
    );
    res.json({ roles, accessToken });
  });
};

module.exports = { handleRefreshToken };
