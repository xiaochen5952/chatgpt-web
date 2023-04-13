import express from 'express'
import bodyParser from 'body-parser'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose'
import type { RequestProps } from './types'
import type { ChatMessage } from './chatgpt'
import { chatConfig, chatReplyProcess, currentModel } from './chatgpt'
import { limiter } from './middleware/limiter'
import { isNotEmptyString } from './utils/is'

const app = express()
const router = express.Router()
// 解析请求体
app.use(bodyParser.json())

// 修改后
function customLogger(message) {
  // 自定义日志输出逻辑，例如将日志写入文件或发送到日志服务
  // ...
}

// 连接 MongoDB 数据库
mongoose.connect('mongodb+srv://xiaochen1649:Guan595212@cluster0.qowmjma.mongodb.net/testp')
//   , {
// // mongoose.connect('mongodb://localhost:27017/test', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true,
// })
  .then(() => {
    customLogger('Connected to MongoDB')
  })
  .catch((error) => {
    console.error('Failed to connect to MongoDB', error)
  })
// 定义用户数据模型
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
  expiration: { type: Date, required: true },
})

const User = mongoose.model('User', userSchema)

// 用户注册
router.post('/register', async (req, res) => {
  const { username, password, expiration } = req.body

  // 使用 bcrypt 进行密码加密
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)

  // 创建新用户
  const newUser = new User({ username, password: hashedPassword, expiration: new Date(Date.now() + expiration * 60 * 60 * 1000) })

  // 保存用户到数据库
  try {
    await newUser.save()
    res.status(201).json({ success: true, message: '用户注册成功' })
  }
  catch (error) {
    res.status(500).json({ success: false, message: '注册失败' })
  }
})

// 用户登录
router.post('/login', async (req, res) => {
  const { username, password } = req.body

  // 查询数据库中是否存在对应的用户
  try {
    const user = await User.findOne({ username })
    if (!user) {
      res.status(401).json({ success: false, message: '用户不存在' })
    }
    else {
      // 验证密码
      if (await bcrypt.compare(password, user.password)) {
        // 计算有效期
        const now = Date.now()
        const expiration = user.expiration.getTime()
        const expiresIn = Math.max(0, Math.floor((expiration - now) / 1000)) // 将有效期转换为秒，并确保不小于0

        // 密码匹配，生成 JWT token
        const token = jwt.sign({ userId: user._id }, 'secretKey', { expiresIn })
        res.json({ token, status: 'Success', expiration, username })
      }
      else {
        res.status(401).json({ success: false, message: '密码错误' })
      }
    }
  }
  catch (error) {
    res.status(500).json({ success: false, message: '登录失败' })
  }
})

// 受保护的 API 路由
router.get('/protected', (req, res) => {
  // 验证 JWT token
  const token = req.headers.authorization.split(' ')[1] // 获取请求头中的 token
  jwt.verify(token, 'secretKey', (error, decoded) => {
    if (error) {
      res.json({ success: false, message: 'token校验失败' })
    }
    else {
      // 验证成功，返回受保护的数据
      res.json({ success: true, message: '访问受保护的路由成功', userId: decoded.userId })
    }
  })
})

const auth1 = async (req, res, next) => {
  try {
    // 验证 JWT token
    const token = req.headers.authorization.split(' ')[1] // 获取请求头中的 token
    jwt.verify(token, 'secretKey', (error, decoded) => {
      if (error) {
        res.status(401).json({ success: false, message: 'token校验失败', status: 'Unauthorized' })
      }
      else {
        // 验证成功，返回受保护的数据
        next()
      }
    })
  }
  catch (error) {
    res.send({ status: 'Unauthorized', message: error.message ?? 'Please authenticate.', data: null })
  }
}

app.use(express.static('public'))
app.use(express.json())

app.all('*', (_, res, next) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Headers', 'authorization, Content-Type')
  res.header('Access-Control-Allow-Methods', '*')
  next()
})

router.post('/chat-process', [auth1, limiter], async (req, res) => {
  res.setHeader('Content-type', 'application/octet-stream')

  try {
    const { prompt, options = {}, systemMessage, temperature, top_p } = req.body as RequestProps
    let firstChunk = true
    await chatReplyProcess({
      message: prompt,
      lastContext: options,
      process: (chat: ChatMessage) => {
        res.write(firstChunk ? JSON.stringify(chat) : `\n${JSON.stringify(chat)}`)
        firstChunk = false
      },
      systemMessage,
      temperature,
      top_p,
    })
  }
  catch (error) {
    res.write(JSON.stringify(error))
  }
  finally {
    res.end()
  }
})

router.post('/config', auth1, async (req, res) => {
  try {
    const response = await chatConfig()
    res.send(response)
  }
  catch (error) {
    res.send(error)
  }
})

router.post('/session', async (req, res) => {
  try {
    const AUTH_SECRET_KEY = process.env.AUTH_SECRET_KEY
    const hasAuth = isNotEmptyString(AUTH_SECRET_KEY)
    res.send({ status: 'Success', message: '', data: { auth: hasAuth, model: currentModel() } })
  }
  catch (error) {
    res.send({ status: 'Fail', message: error.message, data: null })
  }
})

router.post('/verify', async (req, res) => {
  try {
    const { token } = req.body as { token: string }
    if (!token)
      throw new Error('Secret key is empty')

    if (process.env.AUTH_SECRET_KEY !== token)
      throw new Error('密钥无效 | Secret key is invalid')

    res.send({ status: 'Success', message: 'Verify successfully', data: null })
  }
  catch (error) {
    res.send({ status: 'Fail', message: error.message, data: null })
  }
})

app.use('', router)
app.use('/api', router)
app.set('trust proxy', 1)

app.listen(3002, () => globalThis.console.log('Server is running on port 3002'))
