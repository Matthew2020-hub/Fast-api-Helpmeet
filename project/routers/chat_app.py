from fastapi import ( 
    APIRouter,
    Path, 
    status,
    HTTPException, 
    Security
)
from typing import Any
from project.models.user import Estate
import socketio
from models.chat import Room, Message
from library.dependencies.utils import generate_short_id
from library.schemas.websocket import (
    MessageCreate,
    MessagePublic, 
    message_schema
)
from library.dependencies.auth import get_current_user 
from asgiref.sync import sync_to_async

router = APIRouter(prefix="/estate")
sio: Any = socketio.AsyncServer(async_mode="asgi", cors_allow_origin="*")
socket_app = socketio.ASGIApp(sio)
router.mount("/", socket_app)  # Here we mount socket app to main fastapi app


@router.get("/test")
async def test():
    print("test")
    return "WORKS"



@sio.on("connect")
async def connect(sid, env, auth):
    room_id = auth["room_id"]
    if room_id:
        print("SocketIO connect")
        sio.enter_room(sid, room_id)
        await sio.emit("connect", f"Connected as {sid}")
    else:
        raise ConnectionRefusedError('authentication failed')



# # communication with orm
# def store_and_return_message(data):
#     data = data
#     if "room_id" in data:
#         room_id = data["room_id"]
#     else:
#         # raise ConnectionRefusedError("Authentication Failed")
#         room_id = "VGTXC7NJY"
#     room = Room.objects.get(room_id=room_id)
#     instance = Message.objects.create(
#         room=room,
#         author=data["author"],
#         content=data["content"],
#         short_id=generate_short_id(),
#     )
#     instance.save()
#     message = message_schema(instance)
#     return message


# listening to a 'message' event from the client
@sio.on("message")
async def print_message(sid, data):
    print("Socket ID", sid)
    print(data)
    message = await sync_to_async(
        store_and_return_message, thread_sensitive=True)(
        data
    )  # communicating with orm
    print(message)
    await sio.emit("new_message", message, room=message["room_id"])



@router.post(
    "/chat/", response_model=MessagePublic, 
    status_code=status.HTTP_201_CREATED,
    )
async def store_and_return_message(data: MessageCreate,
    current_user =Security(get_current_user, scopes=["base"]),
    ):
    estate_name = current_user.estate_name
    estate = await Estate.get_or_none(estate_name=estate_name)
    if estate is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User Estate does not exist"
        )
    get_room_user = await Room.get(user = estate)
    room = await Room.get(room_id=get_room_user.room_id)
    instance = await Message.create(
        room=room,
        author=current_user,
        content=data.message,
        short_id=generate_short_id(),
    )
    instance.save()
    return instance


@router.get(
    "/chate/messages/{estate_name}",
    status_code=status.HTTP_200_OK,
    response_model=MessagePublic
)
async def get_estate_message(estate_name:str = Path(...)):
    estate = await Estate.get(estate_name=estate_name)
    get_room  = await Room.get(user=estate)
    messages = await Message.filter(room=get_room).select_related("author")
    if messages:
        return messages
    raise HTTPException(    
        status_code=status.HTTP_204_NO_CONTENT,
            detail="No message is available"
        )




@router.get(
    "/messages/all/",
    status_code=status.HTTP_200_OK,
    response_model=MessagePublic
)
async def get_all_messages():
    messages = await Message.all()
    if messages:
        return messages
    raise HTTPException(    
        status_code=status.HTTP_204_NO_CONTENT,
            detail="No message is available"
        )