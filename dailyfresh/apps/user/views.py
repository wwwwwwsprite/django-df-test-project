from django.shortcuts import render,redirect
from django.core.urlresolvers import reverse  # 反向解析函数
from django.contrib.auth import authenticate,login
from django.core.mail import send_mail
from django.views.generic import View
from django.http import HttpResponse
from django.conf import settings

from user.models import User
from utils.mixin import LoginRequiredMixin
from celery_tasks.tasks import send_register_active_email
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import SignatureExpired
import re
# Create your views here.

#  get post put delete
def register(request):
	# 显示注册页面
	if request.method == 'GET':
		# 显示注册页面
		return render(request,'register.html')
	else:
		# 如果不是get请求，就是post请求
		# 注册处理
		# 1 接受数据
		username=request.POST.get('user_name')
		password=request.POST.get('pwd')
		email=request.POST.get('email')
		allow=request.POST.get('allow')

		# 2.进行数据校验
		if not all([username,password,email]):
			# 数据不完整
			return render(request,'register.html',{'errmsg':'数据不完整'})

		if not re.match(r'^[a-z0-9][\w\.\-\_]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$',email):
			return render(request,'register.html',{'errmsg':'邮箱格式不正确'})

		if allow != 'on':
			return render(request,'register.html',{'errmsg':'请同意协议'})

		# 校验用户名重复
		try:
			user = User.objects.get(username=username)
		except:
			# 用户名不存在
			user = None
		if user:
			# 用户名已存在
			return render(request,'register.html',{'errmsg':'用户名已存在'})

		# 3.进行业务处理，用户注册
		user = User.objects.create_user(username,email,password)
		user.is_active = 0
		user.save()

		# 返回应答，跳转到首页
		return redirect(reverse("goods:index"))



class RegisterView(View):
	# 注册类视图
	def get(self, request):
		# 显示注册页面
		return render(request,'register.html')

	def post(self,request):
		# 注册处理
		# 如果不是get请求，就是post请求
		# 注册处理
		# 1 接受数据
		username=request.POST.get('user_name')
		password=request.POST.get('pwd')
		email=request.POST.get('email')
		allow=request.POST.get('allow')

		# 2.进行数据校验
		if not all([username,password,email]):
			# 数据不完整
			return render(request,'register.html',{'errmsg':'数据不完整'})

		if not re.match(r'^[a-z0-9][\w\.\-\_]*@[a-z0-9\-]+(\.[a-z]{2,5}){1,2}$',email):
			return render(request,'register.html',{'errmsg':'邮箱格式不正确'})

		if allow != 'on':
			return render(request,'register.html',{'errmsg':'请同意协议'})

		# 校验用户名重复
		try:
			user = User.objects.get(username=username)
		except:
			# 用户名不存在
			user = None
		if user:
			# 用户名已存在
			return render(request,'register.html',{'errmsg':'用户名已存在'})

		# 3.进行业务处理，用户注册
		user = User.objects.create_user(username,email,password)
		user.is_active = 0
		user.save()

		# 发送接货邮件，包含激活链接：http://127.0.0.1:8000/user/active/1(id)
		# 激活链接中需要包含用户的身份信息，并且把身份信息加密

		# 加密用户的身份信息，生成激活的token
		serializer = Serializer(settings.SECRET_KEY,3600)   #加密信息3600秒后过期
		info = {'confirm': user.id}
		token = serializer.dumps(info)
		token = token.decode()

		# 发送邮件
		send_register_active_email.delay(email,username,token)

		# 返回应答，跳转到首页
		return redirect(reverse("goods:index"))


class ActiveView(View):
	# 用户激活
	def get(self,request,token):
		# 进行用户激活
		serializer = Serializer(settings.SECRET_KEY,3600)   #加密信息3600秒后过期
		try:
			info = serializer.loads(token)
			# 获取激活用户的id
			user_id = info['confirm']
			# 根据id获取用户信息
			user = User.objects.get(id=user_id)
			user.is_active = 1
			user.save()

			# 跳转到登录页面
			return redirect(reverse('user:login'))

		except SignatureExpired as e:
			# 激活链接已过期
			return HttpResponse('激活链接已过期')
		

#  /user/login
class LoginView(View):
	# 登录
	def get(self,request):
		# 判断是否记住了用户名
		if 'username' in request.COOKIES:
			username = request.COOKIES.get('username')
			checked = 'checked'
		else:
			username = ''
			checked = ''
		# 使用模板
		return render(request,'login.html',{'username':username,'checked':checked})

	def post(self,request):
		# 登录校验
		# 接受数据
		username = request.POST.get('username')
		password = request.POST.get('pwd')

		# 校验数据
		if not all([username,password]):
			return render(request,'login.html',{'errmsg':'数据不完整'})

		# 业务处理：登录校验
		# User.objects.get(username=username,password=password)
		user = authenticate(username=username,password=password)
		if user is not None:
			# 用户名或密码正确
			if user.is_active:
				# 用户已激活
				# 记录用户登录状态
				login(request,user)

				# 获取登录后所要跳转的地址,next如果为空就取默认值
				next_url = request.GET.get('next',reverse('goods:index'))

				# 跳转页面
				response = redirect(next_url)

				# 判断是否需要记住用户名
				remember = request.POST.get('remember')
				if remember == 'on':
					# 记住用户名
					response.set_cookie('username',username,max_age=7*24*3600)
				else:
					response.delete_cookie('username')

				#返回response
				return response
				
			else:
				# 用户未激活
				return render(request,'login.html',{'errmsg':'账户未激活'})
		else:
			# 用户名或密码错误
			return render(request,'login.html',{'errmsg':'用户名或密码错误'})

		# 返回应答


# /user
class UserInfoView(LoginRequiredMixin,View):
	# 用户中心-信息页
	def get(self,request):
		# 显示
		return render(request,'user_center_info.html',{'page':'user'})

# /user/order
class UserOrderView(LoginRequiredMixin,View):
	# 用户中心-订单页
	def get(self,request):
		# 显示
		return render(request,'user_center_order.html',{'page':'order'})

# /user/address
class AddressView(LoginRequiredMixin,View):
	# 用户中心-地址页
	def get(self,request):
		# 显示
		return render(request,'user_center_site.html',{'page':'address'})