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
        console.log("Attempted refresh token reuse!");
        const hackedUser = await User.findOne({
          username: decoded.username,
        }).exec();
        hackedUser.refreshToken = [];
        const result = await hackedUser.save();
        console.log({ result });
      }
    );

    return res.sendStatus(403); //Forbidden
  }

  // we find that we have valid refreshToken and now we can reissue the new one
  // but still need to remove old token from refreshToken array in DB
  // and create new array without it
  const newRefreshTokenArray = foundUser.refreshToken.filter(
    (rt) => rt !== refreshToken
  );

  // evaluate jwt
  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      // if we recieve token (and find user with related to) but it expired
      if (err) {
        console.log("Expired refresh token");
        foundUser.refreshToken = [...newRefreshTokenArray];
        const result = await foundUser.save();
        console.log({ result });
      }

      if (err || foundUser.username !== decoded.username)
        return res.sendStatus(403);

      // if refreshToken was still valid
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
      // with this approach we also want to make a new refresh token
      const newRefreshToken = jwt.sign(
        { username: foundUser.username },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "1d" }
      );
      // Saving refreshToken with current user
      foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
      const result = await foundUser.save();

      // Creates Secure Cookie with refresh token
      res.cookie("jwt", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "None",
        maxAge: 24 * 60 * 60 * 1000,
      });
      res.json({ roles, accessToken });
    }
  );
};

module.exports = { handleRefreshToken };
