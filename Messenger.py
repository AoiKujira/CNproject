class Messenger:

    def decode_message(message):
        try:
            message = message.split(maxsplit=3)
            return int(message[0]), int(message[1]), int(message[2]), str(message[3])
        except Exception as e:
            print(e)

    def encode_message(message_type, source_id, destination_id, data):
        message = str(message_type) + '\n' \
                + str(source_id) + '\n' \
                + str(destination_id) + "\n" \
                + str(data)
        return message
