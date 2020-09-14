package Router;

public abstract class BaseLayer {
	String layerName;
	Object upperLayer;
	Object underLayer;
	Object otherUpperLayer;

	public BaseLayer(String layerName) {
		this.layerName = layerName;
	}

	void setUpperLayer(Object upperLayer) {
		this.upperLayer = upperLayer;
	}
	
	void setOtherUpperLayer(Object otherUpperLayer) {
		this.otherUpperLayer = otherUpperLayer;
	}

	void setUnderLayer(Object underLayer) {
		this.underLayer = underLayer;
	}

	Object getOtherUpperLayer() {
		if ((Object) otherUpperLayer == null) {
			System.out.println("[Object-getOtherUnderLayer] There is no otherUnderLayer");
			return null;
		}

		return otherUpperLayer;
	}
	
	Object getUpperLayer() {
		if ((Object) upperLayer == null) {
			System.out.println("[Object-getUpperLayer] There is no UpperLayer");
			return null;
		}

		return upperLayer;
	}

	Object getUnderLayer() {
		if ((Object) underLayer == null) {
			System.out.println("[Object-getUnderLayer] There is no UnderLayer");
			return null;
		}

		return underLayer;
	}

	String getLayerName() {
		return layerName;
	}
}