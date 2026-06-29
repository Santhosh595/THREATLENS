from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from app import Base


class URLAnalysis(Base):
    __tablename__ = 'url_analysis'
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    analysis_result = Column(String)

    def to_dict(self):
        return {"id": self.id, "url": self.url, "result": self.analysis_result}


class ThreatIntelligence(Base):
    __tablename__ = 'threat_intelligence'
    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String, index=True)
    description = Column(String)

    def to_dict(self):
        return {"id": self.id, "type": self.threat_type, "desc": self.description}


class UserSession(Base):
    __tablename__ = 'user_session'
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    session_data = Column(String)

    user = relationship('User', back_populates='sessions')
